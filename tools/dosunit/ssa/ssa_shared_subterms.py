"""Layer: SSA solver preprocessing.

Responsibility: prove scalar equalities after universally abstracting identical
subterms; a failed abstract query is never a concrete counterexample.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import z3

from tools.dosunit.ssa.ssa_modular_scalar import prove_modular_identity


@dataclass(frozen=True)
class SharedScalarProof:
    """Evidence that equality holds for every value of shared scalar subterms."""

    subterms: int
    elapsed_ms: int


def _nodes(expression: z3.ExprRef, limit: int = 4096) -> dict[int, z3.ExprRef] | None:
    """Collect a bounded SMT DAG without expanding shared nodes recursively."""
    result: dict[int, z3.ExprRef] = {}
    pending = [expression]
    while pending:
        term = pending.pop()
        ident = term.get_id()
        if ident in result:
            continue
        if len(result) >= limit:
            return None
        result[ident] = term
        # Binder-local expressions cannot be replaced by global constants:
        # their values may vary with the bound array index. Keep binders opaque.
        if z3.is_app(term):
            pending.extend(term.children())
    return result


def _shared(left: z3.ExprRef, right: z3.ExprRef) -> list[z3.ExprRef]:
    """Choose maximal common non-leaf bitvectors; retain every distinct term."""
    nodes = _nodes(right)
    if nodes is None or _nodes(left) is None:
        return []
    pending, seen, result = [left], set(), []
    while pending:
        term = pending.pop()
        if term.get_id() in seen:
            continue
        seen.add(term.get_id())
        if term.get_id() in nodes and z3.is_bv(term) and z3.is_app(term) and term.num_args():
            result.append(term)
        elif z3.is_app(term):
            pending.extend(term.children())
    return result


def prove_shared_scalar(
    left: z3.ExprRef, right: z3.ExprRef, solver: z3.Solver, *, deadline: float,
) -> SharedScalarProof | None:
    """Prove a stronger equality, or return no result under the original deadline.

    Each identical subterm on both sides becomes one fresh unconstrained value.
    UNSAT therefore covers its real value too. SAT/unknown supplies no claim
    about the original expressions and must fall back to ordinary comparison.
    Caller constraints remain unchanged; no independence premise is added.
    """
    if not z3.is_bv(left) or not z3.is_bv(right) or left.eq(right):
        return None
    started = time.monotonic()
    if started >= deadline:
        return None
    left = z3.simplify(left, blast_select_store=True)
    right = z3.simplify(right, blast_select_store=True)
    shared = _shared(left, right)
    remaining = int((deadline - time.monotonic()) * 1000)
    if not shared or remaining <= 0:
        return None
    replacements = [(term, z3.FreshConst(term.sort(), prefix="shared_scalar")) for term in shared]
    abstract_left = z3.substitute(left, *replacements)
    abstract_right = z3.substitute(right, *replacements)
    if prove_modular_identity(abstract_left, abstract_right, deadline=deadline):
        return SharedScalarProof(len(shared), int((time.monotonic() - started) * 1000))
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        return None
    solver.push()
    try:
        solver.set(timeout=remaining)
        solver.add(abstract_left != abstract_right)
        if solver.check() != z3.unsat or time.monotonic() >= deadline:
            return None
    finally:
        solver.pop()
    return SharedScalarProof(len(shared), int((time.monotonic() - started) * 1000))
