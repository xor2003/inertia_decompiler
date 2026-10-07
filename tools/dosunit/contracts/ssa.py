"""Immutable expressions and explicit lowering refusals.

Layer: dosunit contracts.
Responsibility: preserve SSA tree identity and unsupported-lowering evidence
without depending on VEX, Z3, architecture setup or comparator implementation.
"""

from __future__ import annotations

from dataclasses import dataclass

type SsaExprKey = tuple[str, int, int | None, str | None, tuple[SsaExprKey, ...]]


@dataclass(frozen=True)
class SsaExpr:
    """An operator, its result width and ordered operands or leaf identity.

    Width zero retains the existing memory-array convention. This data owner
    deliberately performs no new validation, folding or architecture inference.
    """

    op: str
    width: int
    args: tuple[SsaExpr, ...] = ()
    value: int | None = None
    name: str | None = None

    def key(self) -> SsaExprKey:
        """Return the existing recursive, ordered structural identity tuple."""
        return (self.op, self.width, self.value, self.name, tuple(arg.key() for arg in self.args))


@dataclass(frozen=True)
class LowerFailure(Exception):
    """Keep the existing refusal reason and diagnostic at a lowering boundary."""

    reason: str
    message: str
