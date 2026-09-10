"""Layer: Code generation/formatting.

Responsibility: render mixed bitwise, shift and logical operands with explicit
grouping for strict C compiler warnings, preserving the existing expression
tree and source-node mapping. No semantic recovery, folding, DCE, type changes
or rendered-text rewriting belongs here. Other architectures retain angr's
renderer. Remove this adapter when the upstream renderer provides this policy.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CClosingObject, CExpression

type _Chunks8616 = Generator[tuple[str, object]]
type _BinaryRenderer8616 = Callable[[CBinaryOp, str], _Chunks8616]
_GROUPED_OPERATORS = frozenset({"And", "Or", "Xor", "Shl", "Shr", "Sar", "LogicalOr"})


class _NamedRenderer8616(Protocol):
    """Installation identity exposed by the third-party renderer method."""

    __name__: str


def _operand_chunks_8616(parent: CBinaryOp, expression: CExpression) -> _Chunks8616:
    """Group a binary operand without mutating its expression or chunk owners."""
    group = isinstance(expression, CBinaryOp) and (
        parent.op_precedence > expression.op_precedence
        or (parent.op in {"And", "Or", "Xor"} and expression.op != parent.op)
        or (parent.op in {"Shl", "Shr", "Sar"} and expression.op in {"Add", "Sub"})
        or (parent.op == "LogicalOr" and expression.op == "LogicalAnd")
    )
    if group:
        parenthesis = CClosingObject("(")
        yield "(", parenthesis
        yield from CExpression._try_c_repr_chunks(expression)
        yield ")", parenthesis
    else:
        yield from CExpression._try_c_repr_chunks(expression)


def apply_codegen_parentheses_8616() -> None:
    """Install the x86-16 grouping policy once at the native render boundary."""
    current = cast(_NamedRenderer8616, CBinaryOp._c_repr_chunks)
    if current.__name__ == "_binary_chunks_8616":
        return
    original = cast(_BinaryRenderer8616, CBinaryOp._c_repr_chunks)

    def _binary_chunks_8616(self: CBinaryOp, op: str) -> _Chunks8616:
        """Preserve native rendering except for explicit mixed-operator grouping."""
        if self.codegen.project.arch.name != "86_16" or self.op not in _GROUPED_OPERATORS:
            yield from original(self, op)
            return
        yield from _operand_chunks_8616(self, self.lhs)
        yield op, self
        yield from _operand_chunks_8616(self, self.rhs)

    CBinaryOp._c_repr_chunks = _binary_chunks_8616
