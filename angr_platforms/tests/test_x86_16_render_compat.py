from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CFunction, CFunctionCall, CReturn, CStatements, CSwitchCase
from angr.sim_variable import SimStackVariable, SimTemporaryVariable
from angr_platforms.X86_16.render_compat import (
    install_structured_codegen_sort_compat_8616,
    repair_cfunctioncall_render_targets_8616,
)


class _NoKbProject:
    kb = None


class _Codegen(SimpleNamespace):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._idx = 0

    def next_idx(self, _name):
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_render_compat_disables_disambiguation_for_projectless_callee():
    codegen = _Codegen(project=_NoKbProject())
    callee = SimpleNamespace(project=None, addr=0x1234, name="helper")
    call = CFunctionCall("helper", callee, [], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([call], codegen=codegen))

    repaired = repair_cfunctioncall_render_targets_8616(codegen)

    assert repaired == 1
    assert call.show_disambiguated_name is False


def test_render_compat_repairs_return_value_call_targets():
    codegen = _Codegen(project=_NoKbProject())
    callee = SimpleNamespace(project=None, addr=0x1234, name="helper")
    call = CFunctionCall("helper", callee, [], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([CReturn(call, codegen=codegen)], codegen=codegen))

    repaired = repair_cfunctioncall_render_targets_8616(codegen)

    assert repaired == 1
    assert call.show_disambiguated_name is False


def test_render_compat_repairs_switch_case_call_targets():
    codegen = _Codegen(project=_NoKbProject())
    callee = SimpleNamespace(project=None, addr=0x1234, name="helper")
    call = CFunctionCall("helper", callee, [], codegen=codegen)
    case_body = CStatements([CReturn(call, codegen=codegen)], codegen=codegen)
    switch = CSwitchCase(SimpleNamespace(), [(69, case_body)], None, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([switch], codegen=codegen))

    repaired = repair_cfunctioncall_render_targets_8616(codegen)

    assert repaired == 1
    assert call.show_disambiguated_name is False


def test_render_compat_sort_local_vars_accepts_none_and_string_idents():
    install_structured_codegen_sort_compat_8616()
    unnamed = SimStackVariable(-2, 2, base="bp", name="local_2", region=0x1000)
    named = SimStackVariable(-2, 2, base="bp", name="local_2_alias", region=0x1000)
    unnamed.ident = None
    named.ident = "local_2_alias"

    assert CFunction.sort_local_vars((named, unnamed)) == [unnamed, named]


def test_render_compat_preserves_temporary_declarations():
    install_structured_codegen_sort_compat_8616()
    first, second = SimTemporaryVariable(0, 4), SimTemporaryVariable(1, 2)
    stack = SimStackVariable(-4, 4, base="bp", ident=None)
    assert CFunction.sort_local_vars((second, stack, first)) == [stack, first, second]
