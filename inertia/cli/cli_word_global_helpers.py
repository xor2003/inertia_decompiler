"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable


class _CodegenFunctionLike(Protocol):
    addr: int


class _CodegenLike(Protocol):
    cfunc: _CodegenFunctionLike


def _make_word_global(codegen: _CodegenLike, addr: int, name: str) -> structured_c.CVariable:
    return structured_c.CVariable(
        SimMemoryVariable(addr, 2, name=name, region=codegen.cfunc.addr),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _synthetic_word_global_variable(
    codegen: _CodegenLike,
    synthetic_globals: dict[int, tuple[str, int]] | None,
    addr: int,
    *,
    synthetic_global_entry: Callable[[dict[int, tuple[str, int]] | None, int], tuple[str, int] | None],
    sanitize_cod_identifier: Callable[[str], str],
    created: dict[int, structured_c.CVariable] | None = None,
) -> structured_c.CVariable | None:
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
