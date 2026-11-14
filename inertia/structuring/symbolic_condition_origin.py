# cython: language_level=3, infer_types=True
"""Preserve AIL branch occurrences through symbolic condition interning.

Layer: Structuring.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
Responsibility: retain distinct proven predicate origins at the angr symbolic
conversion boundary. Equal values do not establish identical CFG occurrences.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from typing import Protocol, cast

import claripy
from claripy.annotation import Annotation
import dataclasses


class _ConditionSurface(Protocol):
    """AIL expression provenance consumed at this boundary."""

    tags: object


class _ProcessorSurface(Protocol):
    """angr's symbolic-expression provenance publication surface."""

    _ast2annotations: object


@dataclasses.dataclass(frozen=True)
class ConditionOriginAnnotation8616:
    """Implement Claripy's annotation protocol with fully owned typed state."""

    source: cython.longlong
    block: cython.longlong

    @property
    def eliminatable(self) -> cython.bint:
        """Refuse simplifications that would erase this branch occurrence."""
        return False

    @property
    def relocatable(self) -> cython.bint:
        """Do not publish an operand's origin as a composite guard's origin."""
        return False

    def relocate(self, _source: object, _destination: object) -> ConditionOriginAnnotation8616:
        """Reject attempts to transfer a branch origin to another expression."""
        raise ValueError("Branch-origin annotations cannot be relocated")


@cython.ccall
def preserve_symbolic_condition_origin_8616(
    processor: object, condition: object, result: claripy.ast.Bool,
) -> claripy.ast.Bool:
    """Separate branch origins in angr's expression-keyed annotation dictionary.

    The protocols describe the third-party ConditionProcessor/AIL boundary.
    Callers must request a branch predicate (must_bool); only complete
    AIL provenance qualifies, and no address is inferred.
    """
    tags = cast(_ConditionSurface, condition).tags
    source, block = tags.get("ins_addr"), tags.get("vex_block_addr")
    if not isinstance(source, int) or not isinstance(block, int):
        return result
    origin = ConditionOriginAnnotation8616(source, block)
    annotated = result if origin in result.annotations else result.annotate(cast(Annotation, origin))
    cast(_ProcessorSurface, processor)._ast2annotations[annotated] = dict(tags)
    return annotated
