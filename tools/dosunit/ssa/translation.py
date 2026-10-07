"""Translate serialized SSA using explicit document-scoped state.

Layer: dosunit SSA solver translation.
Responsibility: resolve inputs and assignment DAGs without importing the engine;
the caller supplies constant normalization and the Z3 backend.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from tools.dosunit.contracts.model import DosUnitError, parse_int
from tools.dosunit.ssa.z3_ops import _resize_z3, apply_operator


class ConstantNormalizer(Protocol):
    """Document policy supplied by the comparison owner."""

    def __call__(self, value: int, *, width: int, document: dict[str, Any],
                 output_name: str | None = None) -> int:
        """Return the admitted constant for this observable output."""
        ...


@dataclass
class TranslationContext:
    """State for one document and output's memoized assignment translation.

    Keep caches separate for outputs with different normalization policies.
    Backend objects remain dynamic only at the external Z3 boundary.
    """

    document: dict[str, Any]
    inputs: dict[str, tuple[Any, int]]
    assignments: dict[str, dict[str, Any]]
    cache: dict[str, Any]
    backend: Any
    normalize_constant: ConstantNormalizer
    output_name: str | None = None

    def term(self, term: dict[str, Any]) -> object:
        """Resolve a leaf or assignment reference under this context."""
        if "ref" in term:
            return self.assignment(str(term["ref"]))
        op = term.get("op")
        width = int(term.get("width", 16))
        if op == "input":
            value, source_width = self.inputs[str(term["name"])]
            return _resize_z3(value, source_width, width, signed=False, z3=self.backend)
        if op == "mem_input":
            return self.inputs[str(term["name"])][0]
        if op == "const":
            value = parse_int(term.get("value"), field="ssa.const")
            value = self.normalize_constant(value, width=width, document=self.document, output_name=self.output_name)
            return self.backend.BitVecVal(value, width)
        raise DosUnitError(f"unsupported SSA term: {term}")

    def assignment(self, ident: str) -> object:
        """Memoize an assignment while preserving operand order and refusal."""
        if ident in self.cache:
            return self.cache[ident]
        item = self.assignments[ident]
        args = [self.term(arg) for arg in item.get("args", []) or []]
        result = apply_operator(str(item.get("op")), int(item.get("width", 16)), args, self.backend)
        self.cache[ident] = result
        return result
