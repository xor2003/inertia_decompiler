from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.lowering.terminal_register_return_values as terminal_register_return_values
from inertia.lowering.terminal_register_return_values import (
    TerminalRegisterReturnValueRefusal8616,
    TerminalRegisterReturnValueStatus8616,
    materialize_terminal_register_return_value_8616,
)

from inertia.semantics.terminal_return_storage import TerminalReturnStorage8616


class _Functions:
    def __init__(self, function: SimpleNamespace) -> None:
        self._function = function

    def function(self, *, addr: int, create: bool) -> SimpleNamespace | None:
        assert create is False
        return self._function if addr == self._function.addr else None


class _Codegen(SimpleNamespace):
    def __init__(self, arch: Arch86_16) -> None:
        super().__init__(cstyle_null_cmp=False, project=SimpleNamespace(arch=arch))
        self._indices: dict[str, int] = {}

    def next_idx(self, kind: str) -> int:
        index = self._indices.get(kind, 0)
        self._indices[kind] = index + 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_terminal_ax_materialization_preserves_explicit_dx_ax_composition(monkeypatch) -> None:
    arch = Arch86_16()
    codegen = _Codegen(arch)
    word_type = SimTypeShort(signed=False).with_arch(arch)
    long_type = SimTypeLong(signed=False).with_arch(arch)
    low = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="low", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    high = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="high", region=0x1000),
        variable_type=word_type,
        codegen=codegen,
    )
    wide_return = structured_c.CBinaryOp(
        "Or",
        structured_c.CBinaryOp(
            "Shl",
            high,
            structured_c.CConstant(16, word_type, codegen=codegen),
            codegen=codegen,
        ),
        low,
        codegen=codegen,
    )
    ax = structured_c.CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=word_type,
        codegen=codegen,
    )
    assignment = structured_c.CAssignment(ax, low, codegen=codegen, tags={"ins_addr": 0x1010})
    return_node = structured_c.CReturn(wide_return, codegen=codegen, tags={"ins_addr": 0x1014})
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        functy=SimTypeFunction([word_type], long_type).with_arch(arch),
        statements=structured_c.CStatements([assignment, return_node], codegen=codegen),
    )
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000})
    project = SimpleNamespace(arch=arch, kb=SimpleNamespace(functions=_Functions(function)))
    monkeypatch.setattr(
        terminal_register_return_values,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_value_8616(project, codegen)

    assert result.status is TerminalRegisterReturnValueStatus8616.REFUSED
    assert result.refusal is TerminalRegisterReturnValueRefusal8616.INCOMPLETE_TERMINAL_SHAPE
    assert return_node.retval is wide_return
