from __future__ import annotations

from types import SimpleNamespace

from angr.sim_variable import SimRegisterVariable

from inertia.cli.cli_local_rewrites import _dedupe_codegen_variable_names_8616


def _make_unique_identifier(name: str, used_names: set[str]) -> str:
    suffix = 2
    while f"{name}_{suffix}" in used_names:
        suffix += 1
    result = f"{name}_{suffix}"
    used_names.add(result)
    return result


def test_name_dedup_refuses_numeric_pseudo_identifiers() -> None:
    first = SimRegisterVariable(0, 2, name="255")
    second = SimRegisterVariable(2, 2, name="255")
    first_cvar = SimpleNamespace(name="255", unified_variable=None)
    second_cvar = SimpleNamespace(name="255", unified_variable=None)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            arg_list=(),
            variables_in_use={first: first_cvar, second: second_cvar},
            unified_local_vars={},
            sort_local_vars=lambda: None,
        )
    )

    changed = _dedupe_codegen_variable_names_8616(
        codegen,
        make_unique_identifier=_make_unique_identifier,
    )

    assert not changed
    assert first.name == "255"
    assert second.name == "255"
    assert first_cvar.name == "255"
    assert second_cvar.name == "255"
