"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c

type ReplaceCChildren = Callable[[object, Callable[[object], object]], bool]


class _CFunctionLike(Protocol):
    """C function shape needed by the MK_FP cleanup helper."""

    statements: object


class _CodegenLike(Protocol):
    """Structured codegen shape needed by the MK_FP cleanup helper."""

    cfunc: _CFunctionLike | None


@dataclass(slots=True)
class _MkFpFold8616:
    """Mutable fold state for the MK_FP cleanup transform."""

    codegen: _CodegenLike
    unwrap_c_casts: Callable[[object], object]
    c_constant_value: Callable[[object], int | None]
    changed: bool = False

    def _is_zero_offset_mk_fp(self, expr: object) -> bool:
        """Return True when an expression is a two-arg MK_FP with zero offset."""
        expr = self.unwrap_c_casts(expr)
        # dynamic codegen boundary: structured C nodes come from angr's codegen classes.
        if not isinstance(expr, structured_c.CFunctionCall) or getattr(expr, "callee_target", None) != "MK_FP":
            return False
        # dynamic codegen boundary: structured C call arguments are provided by angr.
        args = list(getattr(expr, "args", ()) or ())
        if len(args) != 2:
            return False
        return self.c_constant_value(self.unwrap_c_casts(args[1])) == 0

    def transform(self, node: object) -> object:
        """Fold one nested or zero-offset MK_FP node, tracking change."""
        # dynamic codegen boundary: structured C nodes come from angr's codegen classes.
        if not isinstance(node, structured_c.CFunctionCall) or getattr(node, "callee_target", None) != "MK_FP":
            return node
        # dynamic codegen boundary: structured C call arguments are provided by angr.
        args = list(getattr(node, "args", ()) or ())
        if len(args) != 2:
            return node

        seg_expr = self.unwrap_c_casts(args[0])
        off_expr = self.unwrap_c_casts(args[1])
        # dynamic codegen boundary: structured C nodes come from angr's codegen classes.
        if isinstance(seg_expr, structured_c.CFunctionCall) and getattr(seg_expr, "callee_target", None) == "MK_FP":
            # dynamic codegen boundary: structured C call arguments are provided by angr.
            inner_args = list(getattr(seg_expr, "args", ()) or ())
            if len(inner_args) == 2 and self._is_zero_offset_mk_fp(off_expr):
                self.changed = True
                return structured_c.CFunctionCall(
                    "MK_FP",
                    None,
                    [self.unwrap_c_casts(inner_args[0]), self.unwrap_c_casts(inner_args[1])],
                    codegen=self.codegen,
                )
        if self._is_zero_offset_mk_fp(off_expr):
            # dynamic codegen boundary: structured C nodes come from angr's codegen classes.
            inner_args = list(getattr(off_expr, "args", ()) or ())
            if len(inner_args) == 2:
                self.changed = True
                return structured_c.CFunctionCall(
                    "MK_FP",
                    None,
                    [seg_expr, self.unwrap_c_casts(inner_args[0])],
                    codegen=self.codegen,
                )

        return node


def _simplify_nested_mk_fp_calls(
    codegen: _CodegenLike,
    *,
    unwrap_c_casts: Callable[[object], object],
    c_constant_value: Callable[[object], int | None],
    replace_c_children: ReplaceCChildren,
) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False

    folder = _MkFpFold8616(codegen, unwrap_c_casts, c_constant_value)
    root = cfunc.statements
    new_root = folder.transform(root)
    if new_root is not root:
        cfunc.statements = new_root
        root = new_root
        folder.changed = True
    if replace_c_children(root, folder.transform):
        folder.changed = True

    return folder.changed
