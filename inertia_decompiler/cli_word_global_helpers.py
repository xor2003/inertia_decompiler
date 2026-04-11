from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable


def _make_word_global(codegen, addr: int, name: str):
    return structured_c.CVariable(
        SimMemoryVariable(addr, 2, name=name, region=codegen.cfunc.addr),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _synthetic_word_global_variable(
    codegen,
    synthetic_globals: dict[int, tuple[str, int]] | None,
    addr: int,
    *,
    synthetic_global_entry,
    sanitize_cod_identifier,
    created: dict[int, structured_c.CVariable] | None = None,
):
    if created is not None:
        existing = created.get(addr)
        if existing is not None:
            return existing

    symbol = synthetic_global_entry(synthetic_globals, addr)
    if symbol is None:
        return None

    raw_name, width = symbol
    if width < 2:
        return None
    cvar = _make_word_global(codegen, addr, sanitize_cod_identifier(raw_name))
    if created is not None:
        created[addr] = cvar
    return cvar
