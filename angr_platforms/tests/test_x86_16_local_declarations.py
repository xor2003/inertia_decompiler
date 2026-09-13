"""Focused tests for conservative x86-16 local declaration cleanup."""

from __future__ import annotations

from types import SimpleNamespace

import archinfo
import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.postprocess.optimization.dce import _dead_code_elimination_8616
from angr_platforms.X86_16.postprocess.optimization.local_declarations import (
    dedupe_equivalent_stack_local_declarations_8616,
    prune_dce_proven_declarations_8616,
)


class _FakeCodegen:
    def __init__(self) -> None:
        self.cfunc: object | None = None
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self._next_idx = 0

    def next_idx(self, _kind: str) -> int:
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _stack_cvar(
    variable: SimStackVariable,
    codegen: _FakeCodegen,
    *,
    signed: bool = False,
    emitted_name: str | None = None,
) -> structured_c.CVariable:
    unified = None
    if emitted_name is not None:
        unified = SimStackVariable(
            variable.offset,
            variable.size,
            base=variable.base,
            ident=f"unified_{variable.ident}",
            name=emitted_name,
        )
    return structured_c.CVariable(
        variable,
        unified_variable=unified,
        variable_type=SimTypeShort(signed),
        codegen=codegen,
    )


def test_dedupe_equivalent_stack_declarations_across_regions() -> None:
    codegen = _FakeCodegen()
    first = SimStackVariable(-4, 2, base="bp", ident="first", name="local_4", region=0x108D0)
    regenerated = SimStackVariable(-4, 2, base="bp", ident="rebuilt", name="local_4", region=None)
    first_cvar = _stack_cvar(first, codegen, emitted_name="local_4")
    regenerated_cvar = _stack_cvar(regenerated, codegen, emitted_name="local_4")
    variables = {first: first_cvar, regenerated: regenerated_cvar}
    codegen.cfunc = SimpleNamespace(variables_in_use=variables, unified_local_vars={})

    assert dedupe_equivalent_stack_local_declarations_8616(codegen) is True
    assert variables == {first: first_cvar}


def test_dedupe_refuses_conflicting_stack_declaration_types() -> None:
    codegen = _FakeCodegen()
    unsigned = SimStackVariable(-4, 2, base="bp", ident="unsigned", name="local_4", region=0x108D0)
    signed = SimStackVariable(-4, 2, base="bp", ident="signed", name="local_4", region=None)
    variables = {
        unsigned: _stack_cvar(unsigned, codegen),
        signed: _stack_cvar(signed, codegen, signed=True),
    }
    codegen.cfunc = SimpleNamespace(variables_in_use=variables, unified_local_vars={})

    assert dedupe_equivalent_stack_local_declarations_8616(codegen) is False
    assert tuple(variables) == (unsigned, signed)


def test_dedupe_refuses_distinct_stack_declaration_names() -> None:
    codegen = _FakeCodegen()
    local = SimStackVariable(-4, 2, base="bp", ident="local", name="local_4", region=0x108D0)
    alias = SimStackVariable(-4, 2, base="bp", ident="alias", name="saved_bound", region=None)
    variables = {local: _stack_cvar(local, codegen), alias: _stack_cvar(alias, codegen)}
    codegen.cfunc = SimpleNamespace(variables_in_use=variables, unified_local_vars={})

    assert dedupe_equivalent_stack_local_declarations_8616(codegen) is False
    assert tuple(variables) == (local, alias)


def test_dedupe_equivalent_unified_stack_declarations() -> None:
    codegen = _FakeCodegen()
    first = SimStackVariable(-4, 2, base="bp", ident="first", name="local_4", region=0x108D0)
    regenerated = SimStackVariable(-4, 2, base="bp", ident="rebuilt", name="local_4", region=None)
    first_cvar = _stack_cvar(first, codegen)
    regenerated_cvar = _stack_cvar(regenerated, codegen)
    variable_type = SimTypeShort(False).with_arch(codegen.project.arch)
    unified = {
        first: {(first_cvar, variable_type)},
        regenerated: {(regenerated_cvar, variable_type)},
    }
    codegen.cfunc = SimpleNamespace(variables_in_use={}, unified_local_vars=unified)

    assert dedupe_equivalent_stack_local_declarations_8616(codegen) is True
    assert tuple(unified) == (first,)


def test_dedupe_refuses_conflicting_unified_stack_types() -> None:
    codegen = _FakeCodegen()
    first = SimStackVariable(-4, 2, base="bp", ident="first", name="local_4", region=0x108D0)
    regenerated = SimStackVariable(-4, 2, base="bp", ident="rebuilt", name="local_4", region=None)
    first_cvar = _stack_cvar(first, codegen)
    regenerated_cvar = _stack_cvar(regenerated, codegen, signed=True)
    unified = {
        first: {(first_cvar, SimTypeShort(False).with_arch(codegen.project.arch))},
        regenerated: {(regenerated_cvar, SimTypeShort(True).with_arch(codegen.project.arch))},
    }
    codegen.cfunc = SimpleNamespace(variables_in_use={}, unified_local_vars=unified)

    assert dedupe_equivalent_stack_local_declarations_8616(codegen) is False
    assert tuple(unified) == (first, regenerated)


def test_dce_removes_dead_frame_declarations_without_removing_same_named_live_storage():
    """DCE must retire declarations by storage key, never by a colliding name."""
    codegen = _FakeCodegen()
    dead = _stack_cvar(SimStackVariable(0, 2, base="bp", name="local_1"), codegen)
    live = _stack_cvar(SimStackVariable(-2, 2, base="bp", name="local_1"), codegen)
    value = structured_c.CConstant(7, SimTypeShort(False), codegen=codegen)
    root = structured_c.CStatements([
        structured_c.CAssignment(dead, value, codegen=codegen),
        structured_c.CReturn(live, codegen=codegen),
    ], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=root, arg_list=[],
        variables_in_use={dead.variable: dead, live.variable: live},
        unified_local_vars={
            dead.variable: {(dead, dead.variable_type)},
            live.variable: {(live, live.variable_type)},
        },
    )
    assert _dead_code_elimination_8616(codegen)
    assert len(root.statements) == 1
    assert tuple(codegen.cfunc.variables_in_use) == (live.variable,)
    assert tuple(codegen.cfunc.unified_local_vars) == (live.variable,)


@pytest.mark.parametrize("entry", [None, set(), [(object(), None)], ["unknown"]])
def test_dce_declaration_cleanup_refuses_unknown_unified_entries(entry):
    """Missing declaration identity is not evidence that storage is dead."""
    codegen = _FakeCodegen()
    variable = SimStackVariable(0, 2, base="bp", name="slot")
    declarations = {variable: entry}
    codegen.cfunc = SimpleNamespace(variables_in_use={}, unified_local_vars=declarations)
    assert not prune_dce_proven_declarations_8616(
        codegen, dead_keys=frozenset({("stack", 0)}),
        key_of=lambda cvar: ("stack", cvar.variable.offset),
    )
    assert declarations == {variable: entry}
