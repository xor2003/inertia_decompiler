# cython: language_level=3, infer_types=True
"""Materialize explicit C spellings for proven scalar character signedness.

Layer: Types/Lowering.
Responsibility: preserve existing scalar ``SimTypeChar`` signedness when angr
renders typed C declarations. This module does not infer signedness and does
not inspect assembly, source, sidecars, or rendered C text.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

angr's ``SimTypeChar.c_repr()`` emits plain ``char`` for both signed and
unsigned instances. On hosts where plain ``char`` is signed, that loses the
already-recovered ``signed=False`` contract and can change byte MUL/DIV
behavior. The lowering below gives scalar character types an explicit C label;
pointee and aggregate element types remain untouched.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeFunction

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
import dataclasses
import operator

__all__ = [
    "ExplicitScalarCharTypeStats8616",
    "explicit_scalar_char_type_8616",
    "materialize_explicit_scalar_char_types_8616",
]


@dataclasses.dataclass(frozen=True, )
class ExplicitScalarCharTypeStats8616:
    """Closed evidence counters for explicit scalar character type spelling."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong


class _CFunctionExplicitCharTypes8616(Protocol):
    """Third-party structured C function fields consumed by this lowering."""

    statements: object | None
    variables_in_use: object
    unified_local_vars: object
    arg_list: object
    functy: SimTypeFunction


class _CodegenExplicitCharTypes8616(Protocol):
    """Dynamic codegen boundary used by explicit character type lowering."""

    cfunc: _CFunctionExplicitCharTypes8616 | None
    _inertia_explicit_scalar_char_type_stats_8616: ExplicitScalarCharTypeStats8616


@cython.ccall
def explicit_scalar_char_type_8616(type_: object) -> object:
    """Return an explicitly rendered equivalent of one scalar character type."""
    if not isinstance(type_, SimTypeChar) or not isinstance(type_.signed, bool):
        return type_
    label = "signed char" if type_.signed else "unsigned char"
    if operator.eq(type_.label, label):
        return type_
    explicit = SimTypeChar(
        signed=type_.signed,
        label=label,
        qualifier=type_.qualifier,
    )
    if type_._arch is not None:
        explicit = explicit.with_arch(type_._arch)
    return explicit


@cython.dataclasses.dataclass()
class _ExplicitCharTypeStats8616:
    """Mutable closed counters collected while normalizing scalar type slots."""

    raw_count: cython.longlong = 0
    normalized_count: cython.longlong = 0
    classified_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    changed: cython.bint = False

    @cython.ccall
    def normalize(self, type_: object) -> object:
        """Normalize one scalar type slot and update the closed counters."""
        if not isinstance(type_, SimTypeChar):
            return type_
        self.raw_count += 1
        if not isinstance(type_.signed, bool):
            return type_
        self.normalized_count += 1
        self.classified_count += 1
        explicit = explicit_scalar_char_type_8616(type_)
        if isinstance(explicit, SimTypeChar) and explicit.label in {"signed char", "unsigned char"}:
            self.materialized_count += 1
        if explicit is not type_:
            self.changed = True
        return explicit


@cython.ccall
def _char_typed_cvariables_8616(
    cfunc: _CFunctionExplicitCharTypes8616,
) -> object:
    """Collect every reachable ``CVariable`` surface by object identity."""
    cvar: object
    node: object
    cvariables: dict[cython.longlong, structured_c.CVariable] = {}
    for cvar in cfunc.variables_in_use.values():
        cvariables[id(cvar)] = cvar
    for cvar in cfunc.arg_list:
        cvariables[id(cvar)] = cvar
    if cfunc.statements is not None:
        for node in _iter_c_nodes_deep_8616(cfunc.statements):
            if isinstance(node, structured_c.CVariable):
                cvariables[id(node)] = node
    return cvariables


def materialize_explicit_scalar_char_types_8616(codegen: object) -> cython.bint:
    """Preserve known scalar character signedness in structured C declarations."""
    cfunc: object
    cvar: object
    entries: object
    variable: object
    variable_type: object
    typed_codegen = cast(_CodegenExplicitCharTypes8616, codegen)
    cfunc = typed_codegen.cfunc
    if cfunc is None:
        typed_codegen._inertia_explicit_scalar_char_type_stats_8616 = ExplicitScalarCharTypeStats8616(
            0, 0, 0, 0, 0
        )
        return False

    stats = _ExplicitCharTypeStats8616()

    for cvar in _char_typed_cvariables_8616(cfunc).values():
        cvar.variable_type = cast(SimType | None, stats.normalize(cvar.variable_type))

    for variable, entries in tuple(cfunc.unified_local_vars.items()):
        rebuilt: set[tuple[structured_c.CVariable, object]] = set()
        for cvar, variable_type in entries:
            rebuilt.add((cvar, stats.normalize(variable_type)))
        cfunc.unified_local_vars[variable] = rebuilt

    cfunc.functy.returnty = cast(SimType | None, stats.normalize(cfunc.functy.returnty))
    cfunc.functy.args = tuple(
        cast(SimType, stats.normalize(arg_type)) for arg_type in iter(cfunc.functy.args)
    )

    typed_codegen._inertia_explicit_scalar_char_type_stats_8616 = ExplicitScalarCharTypeStats8616(
        raw_fact_count=stats.raw_count,
        normalized_fact_count=stats.normalized_count,
        classified_fact_count=stats.classified_count,
        materialized_count=stats.materialized_count,
        failure_count=max(stats.classified_count - stats.materialized_count, 0),
    )
    return stats.changed
