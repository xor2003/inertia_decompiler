"""Exact sparse unread-mask commutation before uninterpreted base projection.

Layer: SSA solver lowering. Responsibility: distribute projection through stores
and pointwise choices without changing actual memory or adding entry premises.
The exact zero-mask interpretation satisfies every rewrite; uninterpreted base
projections remain an overapproximation, including at the traversal depth cap.
"""
from __future__ import annotations

from typing import Any


class _Projection:
    """Memoized exact rewrites with an uninterpreted fallback."""

    def __init__(self, memory: Any, first: int, last: int, z3: Any) -> None:  # noqa: ANN401
        """Bind the unread interval and shared base projection symbol."""
        self.z3, self.first, self.last = z3, first, last
        self.base = z3.Function(f"unread_projection_{first:x}_{last:x}",
                                memory.sort(), memory.sort())
        self.memo: dict[int, Any] = {}
        self.closed_memo: dict[tuple[int, int], tuple[Any, bool]] = {}

    def closed(self, term: Any, depth: int = 0) -> bool:  # noqa: ANN401
        """Reject free de Bruijn indices; nested Lambda binders remain local."""
        z3 = self.z3
        key = (term.get_id(), depth)
        cached = self.closed_memo.get(key)
        if cached is not None:
            return cached[1]
        if z3.is_var(term):
            result = bool(z3.get_var_index(term) < depth)
        elif z3.is_quantifier(term):
            result = self.closed(term.body(), depth + term.num_vars())
        else:
            result = all(self.closed(child, depth) for child in term.children())
        # Retain the AST so its context-local ID cannot be recycled during use.
        self.closed_memo[key] = (term, result)
        return result

    def pointwise(self, memory: Any, depth: int) -> Any:  # noqa: ANN401
        """Distribute through choices whose array branches cannot capture indices."""
        z3 = self.z3
        fallback = self.base(memory)
        if z3.is_app_of(memory, z3.Z3_OP_ITE):
            return z3.If(memory.arg(0), self.project(memory.arg(1), depth + 1),
                         self.project(memory.arg(2), depth + 1))
        if not (z3.is_quantifier(memory) and memory.is_lambda() and memory.num_vars() == 1):
            return fallback
        body = memory.body()
        if not z3.is_app_of(body, z3.Z3_OP_ITE):
            return fallback
        left, right = body.arg(1), body.arg(2)
        index = z3.Var(0, z3.BitVecSort(32))
        if not (z3.is_select(left) and z3.is_select(right)):
            return fallback
        if not (left.arg(1).eq(index) and right.arg(1).eq(index)
                and self.closed(left.arg(0)) and self.closed(right.arg(0))
                and self.closed(body.arg(0), 1)):
            return fallback
        address = z3.FreshConst(z3.BitVecSort(32), "projected_byte")
        condition = z3.substitute_vars(body.arg(0), address)
        return z3.Lambda(address, z3.If(
            condition, z3.Select(self.project(left.arg(0), depth + 1), address),
            z3.Select(self.project(right.arg(0), depth + 1), address)))

    def project(self, memory: Any, depth: int = 0) -> Any:  # noqa: ANN401
        """Commute stores and choices, bounding recursive choice traversal."""
        z3 = self.z3
        key = memory.get_id()
        if key in self.memo:
            return self.memo[key]
        if depth >= 128:
            return self.base(memory)
        updates = []
        base = memory
        while z3.is_store(base):
            updates.append((base.arg(1), base.arg(2)))
            base = base.arg(0)
        result = self.pointwise(base, depth)
        for address, value in reversed(updates):
            inside = z3.And(z3.UGE(address, self.first), z3.ULE(address, self.last))
            result = z3.If(inside, result, z3.Store(result, address, value))
        self.memo[key] = result
        return result


def project_unread_array(memory: Any, first: int, last: int, z3: Any) -> Any:  # noqa: ANN401
    """Return exact commutations over an overapproximating base projection."""
    return z3.simplify(_Projection(memory, first, last, z3).project(memory))
