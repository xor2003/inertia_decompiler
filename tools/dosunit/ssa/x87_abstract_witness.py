"""Layer: SSA counterexample validation.

Responsibility: distinguish exact output witnesses from arbitrary models of
the declared, uninterpreted x87 transcendental approximation functions.
"""

from __future__ import annotations

from dataclasses import dataclass

import z3


def _contains_approximation(root: z3.ExprRef) -> bool:
    """Inspect each backend DAG node once, including quantified bodies."""
    pending = [root]
    seen: set[int] = set()
    while pending:
        term = pending.pop()
        ident = term.get_id()
        if ident in seen:
            continue
        seen.add(ident)
        if z3.is_quantifier(term):
            pending.append(term.body())
        elif z3.is_app(term):
            declaration = term.decl()
            if declaration.kind() == z3.Z3_OP_UNINTERPRETED and str(declaration.name()).startswith("x87_trans_"):
                return True
            pending.extend(term.children())
    return False


def _depends_on_approximation(term: z3.ExprRef) -> bool:
    """Discard only dependencies eliminated by exact backend simplification."""
    return _contains_approximation(term) and _contains_approximation(z3.simplify(term))


@dataclass(frozen=True)
class X87CounterexampleScope:
    """Outputs whose modeled values need no transcendental interpretation."""

    exact_outputs: frozenset[str]
    abstract_outputs: tuple[str, ...]
    abstract_domain: bool


def counterexample_scope(
    pairs: list[tuple[str, z3.ExprRef, z3.ExprRef]], domain_guards: list[z3.ExprRef],
) -> X87CounterexampleScope:
    """Identify usable witnesses while retaining every asserted domain guard."""
    abstract = tuple(name for name, left, right in pairs
                     if _depends_on_approximation(left) or _depends_on_approximation(right))
    abstract_domain = any(_depends_on_approximation(guard) for guard in domain_guards)
    exact = frozenset(name for name, _, _ in pairs if name not in abstract)
    return X87CounterexampleScope(exact, abstract, abstract_domain)
