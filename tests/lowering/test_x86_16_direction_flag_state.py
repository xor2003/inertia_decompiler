"""Focused tests for explicit direction-step runtime state."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeLong
from angr.sim_variable import SimRegisterVariable
import inertia.lowering.direction_flag_state as direction_flag_state


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


def test_opaque_direction_assignment_uses_explicit_runtime_state(monkeypatch) -> None:
    """An unrenderable incoming VEX d expression becomes inertia_direction."""
    codegen = _Codegen(project=SimpleNamespace(arch=SimpleNamespace(registers={"d": (52, 4)})))
    direction = structured_c.CVariable(
        SimRegisterVariable(52, 4, ident="d_1", region=0x100),
        variable_type=SimTypeLong(True),
        codegen=codegen,
    )
    assignment = structured_c.CAssignment(
        direction,
        structured_c.CDirtyExpression(SimpleNamespace(), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x100, statements=structured_c.CStatements([assignment], codegen=codegen))
    monkeypatch.setattr(direction_flag_state, "record_global_declaration_spec_8616", lambda *_args, **_kwargs: None)

    assert direction_flag_state.lower_direction_flag_state_8616(codegen) is True
    assert isinstance(assignment.rhs, structured_c.CVariable)
    assert assignment.rhs.variable.name == "inertia_direction"
    assert assignment.rhs.variable.size == 4


def test_concrete_cld_std_direction_assignment_is_preserved(monkeypatch) -> None:
    """Proven constant direction writes remain owned by instruction semantics."""
    codegen = _Codegen(project=SimpleNamespace(arch=SimpleNamespace(registers={"d": (52, 4)})))
    direction = structured_c.CVariable(
        SimRegisterVariable(52, 4, ident="d_1", region=0x100),
        variable_type=SimTypeLong(True),
        codegen=codegen,
    )
    constant = structured_c.CConstant(-1, SimTypeLong(True), codegen=codegen)
    assignment = structured_c.CAssignment(direction, constant, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x100, statements=structured_c.CStatements([assignment], codegen=codegen))
    monkeypatch.setattr(direction_flag_state, "record_global_declaration_spec_8616", lambda *_args, **_kwargs: None)

    assert direction_flag_state.lower_direction_flag_state_8616(codegen) is False
    assert assignment.rhs is constant
