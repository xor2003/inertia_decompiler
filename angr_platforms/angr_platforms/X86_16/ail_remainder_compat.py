"""Install the IR-owned remainder identity at angr's optimization boundary.

Layer: Frontend/IR adapter.
Responsibility: dispatch x86-16 modulo normalization to its lossless IR owner.
Other architectures retain their existing optimizer. No rendered-C recovery.
"""

from __future__ import annotations

from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Expression
from angr.analyses.decompiler.peephole_optimizations.modulo_simplifier import ModuloSimplifier

from .ir.ail_remainder import fold_integer_remainder_8616


def apply_remainder_compatibility_8616() -> None:
    """Replace the native x86-16 fold once, preserving other architecture behavior."""
    original = ModuloSimplifier.optimize
    if original.__name__ == "_remainder_8616":
        return

    def _remainder_8616(
        self: ModuloSimplifier,
        expr: BinaryOp,
        stmt_idx: int | None = None,
        block: Block | None = None,
        **kwargs: object,
    ) -> Expression | None:
        """Preserve typed division evidence before native simplification loses it."""
        if self.project is not None and self.project.arch.name == "86_16":
            return fold_integer_remainder_8616(expr)
        return original(self, expr, stmt_idx=stmt_idx, block=block, **kwargs)

    ModuloSimplifier.optimize = _remainder_8616
