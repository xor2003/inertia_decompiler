from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CStatements, CVariable
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.explicit_char_types import (
    materialize_explicit_scalar_char_types_8616,
)


class _DummyCodegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_explicit_char_types_preserve_scalar_signedness_without_retyping_pointers() -> None:
    codegen = _DummyCodegen()
    unsigned_type = SimTypeChar(False).with_arch(codegen.project.arch)
    signed_type = SimTypeChar(True).with_arch(codegen.project.arch)
    pointer_type = SimTypePointer(SimTypeChar(False)).with_arch(codegen.project.arch)
    unsigned_variable = SimStackVariable(-2, 1, base="bp", name="value")
    signed_variable = SimRegisterVariable(0, 1, name="al_value")
    pointer_variable = SimRegisterVariable(2, 2, name="text")
    unsigned_cvar = CVariable(unsigned_variable, variable_type=unsigned_type, codegen=codegen)
    signed_cvar = CVariable(signed_variable, variable_type=signed_type, codegen=codegen)
    pointer_cvar = CVariable(pointer_variable, variable_type=pointer_type, codegen=codegen)
    root = CStatements([unsigned_cvar, signed_cvar, pointer_cvar], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=root,
        variables_in_use={
            unsigned_variable: unsigned_cvar,
            signed_variable: signed_cvar,
            pointer_variable: pointer_cvar,
        },
        unified_local_vars={
            unsigned_variable: {(unsigned_cvar, unsigned_type)},
            signed_variable: {(signed_cvar, signed_type)},
            pointer_variable: {(pointer_cvar, pointer_type)},
        },
        arg_list=[signed_cvar],
        functy=SimTypeFunction([signed_type], unsigned_type).with_arch(codegen.project.arch),
    )

    changed = materialize_explicit_scalar_char_types_8616(codegen)

    assert changed is True
    assert unsigned_cvar.variable_type.c_repr(name="value") == "unsigned char value"
    assert signed_cvar.variable_type.c_repr(name="al_value") == "signed char al_value"
    assert pointer_cvar.variable_type is pointer_type
    unified_unsigned_type = next(iter(codegen.cfunc.unified_local_vars[unsigned_variable]))[1]
    assert unified_unsigned_type.c_repr(name="value") == "unsigned char value"
    assert codegen.cfunc.functy.returnty.c_repr(name="result") == "unsigned char result"
    assert codegen.cfunc.functy.args[0].c_repr(name="arg") == "signed char arg"
    stats = codegen._inertia_explicit_scalar_char_type_stats_8616
    assert stats.raw_fact_count == 6
    assert stats.normalized_fact_count == 6
    assert stats.classified_fact_count == 6
    assert stats.materialized_count == 6
    assert stats.failure_count == 0


def test_explicit_char_type_materialization_is_idempotent() -> None:
    codegen = _DummyCodegen()
    explicit_type = SimTypeChar(False, label="unsigned char").with_arch(codegen.project.arch)
    variable = SimStackVariable(-2, 1, base="bp", name="value")
    cvar = CVariable(variable, variable_type=explicit_type, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([cvar], codegen=codegen),
        variables_in_use={variable: cvar},
        unified_local_vars={variable: {(cvar, explicit_type)}},
        arg_list=[],
        functy=SimTypeFunction([], SimTypeShort(False)).with_arch(codegen.project.arch),
    )

    changed = materialize_explicit_scalar_char_types_8616(codegen)

    assert changed is False
    stats = codegen._inertia_explicit_scalar_char_type_stats_8616
    assert stats.classified_fact_count == 2
    assert stats.materialized_count == 2
    assert stats.failure_count == 0
