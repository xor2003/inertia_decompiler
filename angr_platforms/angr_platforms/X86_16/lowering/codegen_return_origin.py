"""Transport return-value origins across native AIL-to-C conversion.

Layer: Types/Lowering.
Responsibility: preserve existing per-use instruction provenance on C returns,
not on interned C variables. This is source identity, not semantic proof.
Consumers must join it to IR/CFG and Alias evidence before accepting a value.
No value, path, storage, signature or return expression is recovered here.
Consumes alias, widening, and typed facts; this adapter transports origin metadata.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr import ailment
from angr.analyses.decompiler.structured_codegen.c import CReturn, CStructuredCodeGenerator

_ORIGIN_TAG = "inertia_x86_16_return_value_origin"


@dataclass(frozen=True, slots=True)
class ReturnValueOrigin8616:
    """Original AIL value location and width for one C return use."""

    instruction_addr: int
    block_addr: int
    width_bits: int


class _ValueSurface8616(Protocol):
    """Native Python/Rust AIL expression fields consumed without interpretation."""

    tags: Mapping[str, object]
    bits: object


def _nonnegative_integer(value: object) -> int | None:
    """Reject malformed metadata, including Boolean values disguised as integers."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _ail_value_origin(statement: ailment.Stmt.Return) -> ReturnValueOrigin8616 | None:
    """Read complete source metadata for exactly one returned AIL value."""
    if len(statement.ret_exprs) != 1:
        return None
    value = cast(_ValueSurface8616, statement.ret_exprs[0])
    try:
        instruction = _nonnegative_integer(value.tags["ins_addr"])
        block = _nonnegative_integer(value.tags["vex_block_addr"])
        width = _nonnegative_integer(value.bits)
    except (AttributeError, KeyError, TypeError):
        return None
    if instruction is None or block is None or width is None or width == 0:
        return None
    return ReturnValueOrigin8616(instruction, block, width)


def return_value_origin_8616(statement: CReturn) -> ReturnValueOrigin8616 | None:
    """Read transported source identity without treating it as value-flow proof."""
    origin = statement.tags.get(_ORIGIN_TAG)
    return origin if isinstance(origin, ReturnValueOrigin8616) else None


def apply_codegen_return_origin_8616() -> None:
    """Install an idempotent x86-16 adapter at native return construction."""
    # The native untyped converter accepts backend-specific keyword arguments.
    original = cast(Callable[..., CReturn], CStructuredCodeGenerator._handle_Stmt_Return)
    if original.__name__ == "_return_with_value_origin_8616":
        return

    def _return_with_value_origin_8616(
        self: CStructuredCodeGenerator, statement: ailment.Stmt.Return, **kwargs: object,
    ) -> CReturn:
        """Keep native values and copy source metadata onto the owning return use."""
        result = original(self, statement, **kwargs)
        if self.project.arch.name != "86_16":
            return result
        origin = _ail_value_origin(statement)
        # Native conversion shares the AIL statement's dictionary. Never mutate
        # it, or place a per-use origin on a CVariable shared by other returns.
        result.tags = dict(result.tags)
        result.tags.pop(_ORIGIN_TAG, None)
        if origin is not None:
            result.tags[_ORIGIN_TAG] = origin
        return result

    CStructuredCodeGenerator._handle_Stmt_Return = _return_with_value_origin_8616
