# cython: language_level=3, infer_types=True
"""Preserve materialized call arguments without reusable object-id aliases.

Layer: Types/Lowering.
Responsibility: retain already proven call arguments across bounded C-AST
regeneration while requiring exact call-object identity on every lookup.
This module does not recover argument values or inspect rendered C text.

Consumes alias, widening, and typed facts only after their materialization into
owned call-expression state. Do not recover semantics from COD, source,
assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass, field
from typing import Any
import dataclasses

# Opaque angr structured-codegen values are intentionally dynamic at this
# boundary; mypyc cannot import dataclass fields annotated as builtin object.
OpaqueCodegenValue8616 = typing.TypeAliasType("OpaqueCodegenValue8616", Any)


@dataclasses.dataclass(frozen=True, )
class ProtectedCallArgument8616:
    """One quality-ranked argument tied to its original structured call."""

    call: OpaqueCodegenValue8616
    expression: OpaqueCodegenValue8616
    score: cython.longlong


@cython.dataclasses.dataclass()
class ProtectedCallArgumentStore8616:
    """Identity-verified protected arguments for one codegen lifecycle."""

    entries: object = field(default_factory=dict)

    @cython.ccall
    def get(self, call: OpaqueCodegenValue8616, argument_index: cython.longlong) -> ProtectedCallArgument8616 | None:
        """Return an entry only when the retained call is the exact live object."""
        entry: object
        entry = self.entries.get((id(call), argument_index))
        return entry if entry is not None and entry.call is call else None

    @cython.ccall
    def remember(
        self,
        call: OpaqueCodegenValue8616,
        argument_index: cython.longlong,
        expression: OpaqueCodegenValue8616,
        score: cython.longlong,
    ) -> None:
        """Retain the highest-quality expression for one exact live call argument."""
        current: object
        current = self.get(call, argument_index)
        if current is None or score >= current.score:
            self.entries[(id(call), argument_index)] = ProtectedCallArgument8616(
                call=call,
                expression=expression,
                score=score,
            )

    @cython.ccall
    def discard_call(self, call: OpaqueCodegenValue8616) -> None:
        """Discard every protected argument owned by one exact call object."""
        entry: object
        key: object
        for key, entry in tuple(self.entries.items()):
            if entry.call is call:
                del self.entries[key]


__all__ = ["ProtectedCallArgument8616", "ProtectedCallArgumentStore8616"]
