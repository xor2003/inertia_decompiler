from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CIfElse,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from inertia.lowering.global_symbol_names import (
    DSGlobalLocalDeclarationStats8616,
    DSGlobalSymbolNameFact8616,
    reconcile_ds_global_local_declarations_8616,
    synchronize_ds_global_symbol_names_8616,
)
from archinfo import ArchX86


class _Codegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=ArchX86())
        self.cstyle_null_cmp = False
        self._next_index = 0
        self.cfunc = SimpleNamespace(
            statements=CStatements([], codegen=self),
            unified_local_vars={},
            variables_in_use={},
        )

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _global(codegen: _Codegen, name: str, *, width: int = 2) -> CVariable:
    return CVariable(
        SimMemoryVariable(0x7000, width, name=name, region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def test_global_symbol_name_sync_reaches_current_angr_if_branches() -> None:
    codegen = _Codegen()
    condition = _global(codegen, "BadWeather")
    assignment_lhs = _global(codegen, "_S767_BadWeather")
    assignment = CAssignment(
        assignment_lhs,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(
        CIfElse(
            [(condition, CStatements([assignment], codegen=codegen))],
            codegen=codegen,
        )
    )

    changed = synchronize_ds_global_symbol_names_8616(
        codegen,
        (DSGlobalSymbolNameFact8616(0x7000, 2, "_S767_BadWeather"),),
    )

    assert changed is True
    assert condition.name == "_S767_BadWeather"
    assert assignment_lhs.name == "_S767_BadWeather"


def test_global_symbol_name_sync_requires_exact_width() -> None:
    codegen = _Codegen()
    byte_view = _global(codegen, "byte_view", width=1)
    codegen.cfunc.statements.statements.append(byte_view)

    changed = synchronize_ds_global_symbol_names_8616(
        codegen,
        (DSGlobalSymbolNameFact8616(0x7000, 2, "word_view"),),
    )

    assert changed is False
    assert byte_view.name == "byte_view"


def test_global_symbol_name_sync_refuses_conflicting_exact_facts() -> None:
    codegen = _Codegen()

    with pytest.raises(ValueError, match="conflicting names"):
        synchronize_ds_global_symbol_names_8616(
            codegen,
            (
                DSGlobalSymbolNameFact8616(0x7000, 2, "first"),
                DSGlobalSymbolNameFact8616(0x7000, 2, "second"),
            ),
        )


def test_global_identity_reconciliation_removes_only_exact_stale_local_surface() -> None:
    codegen = _Codegen()
    global_cvar = _global(codegen, "g_7000")
    global_variable = global_cvar.variable
    carrier = SimRegisterVariable(0, 2, name="vvar_1", region=0x1000)
    local = SimStackVariable(-2, 2, base="bp", name="local_2", region=0x1000)
    unrelated_global = SimMemoryVariable(0x7002, 2, name="g_7002", region=0x1000)
    codegen.cfunc.statements.statements.append(global_cvar)
    codegen.cfunc.unified_local_vars = {
        global_variable: {(global_cvar, SimTypeShort(False))},
        local: set(),
        unrelated_global: set(),
    }
    codegen.cfunc.variables_in_use = {
        carrier: global_cvar,
        global_variable: global_cvar,
        local: CVariable(local, variable_type=SimTypeShort(False), codegen=codegen),
    }
    facts = (DSGlobalSymbolNameFact8616(0x7000, 2, "g_7000"),)

    changed = reconcile_ds_global_local_declarations_8616(codegen, facts)

    assert changed is True
    assert global_variable not in codegen.cfunc.unified_local_vars
    assert local in codegen.cfunc.unified_local_vars
    assert unrelated_global in codegen.cfunc.unified_local_vars
    assert carrier not in codegen.cfunc.variables_in_use
    assert global_variable in codegen.cfunc.variables_in_use
    assert local in codegen.cfunc.variables_in_use
    assert codegen._inertia_ds_global_local_declaration_stats_8616 == (
        DSGlobalLocalDeclarationStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=2,
            materialized_count=2,
            failure_count=0,
        )
    )

    assert reconcile_ds_global_local_declarations_8616(codegen, facts) is False
