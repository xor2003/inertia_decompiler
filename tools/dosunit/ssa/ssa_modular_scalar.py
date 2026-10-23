"""Layer: SSA solver preprocessing.

Responsibility: prove bitvector polynomial identities using exact bounded
integer arithmetic, preserving every intermediate modular truncation.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from math import gcd

import z3


@dataclass(frozen=True)
class BoundedInteger:
    """Unsigned integer interpretation and conservative inclusive bounds."""

    term: z3.ArithRef
    low: int
    high: int


def _combine(expression: z3.ExprRef, children: list[BoundedInteger]) -> BoundedInteger:
    """Interpret admitted arithmetic before its result-width truncation."""
    kind = expression.decl().kind()
    if kind == z3.Z3_OP_BADD:
        return BoundedInteger(z3.Sum([c.term for c in children]),
                              sum(c.low for c in children), sum(c.high for c in children))
    if kind == z3.Z3_OP_BMUL:
        left, right = children
        return BoundedInteger(left.term * right.term, left.low * right.low, left.high * right.high)
    term, low, high = z3.IntVal(0), 0, 0
    for child, source in zip(children, expression.children(), strict=True):
        factor = 1 << source.size()
        term, low, high = term * factor + child.term, low * factor + child.low, high * factor + child.high
    return BoundedInteger(term, low, high)


def _admitted(expression: z3.ExprRef) -> bool:
    """Keep unsupported operations atomic and multiplication linear."""
    if not z3.is_app(expression):
        return False
    kind = expression.decl().kind()
    return kind in {z3.Z3_OP_BADD, z3.Z3_OP_CONCAT} or (
        kind == z3.Z3_OP_BMUL and expression.num_args() == 2
        and any(z3.is_bv_value(child) for child in expression.children()))


def _residue(
    term: z3.ArithRef, modulus: int, depth: int = 0, budget: list[int] | None = None,
) -> z3.ArithRef:
    """Remove only truncations invisible modulo the requested result width.

    Multiplication by k observes its operand modulo M/gcd(k,M). A remainder
    modulo D can be dropped only when D is a multiple of that observed modulus.
    The returned expression is congruent, not necessarily range bounded.
    """
    if budget is None:
        budget = [8192]
    budget[0] -= 1
    if depth >= 128 or budget[0] <= 0:
        return term
    kind = term.decl().kind()
    if kind == z3.Z3_OP_ADD:
        return z3.Sum([_residue(child, modulus, depth + 1, budget) for child in term.children()])
    if kind == z3.Z3_OP_MUL and term.num_args() == 2:
        left, right = term.children()
        if z3.is_int_value(right):
            left, right = right, left
        if z3.is_int_value(left):
            factor = left.as_long()
            return factor * _residue(right, modulus // gcd(factor, modulus), depth + 1, budget)
    if kind == z3.Z3_OP_MOD and z3.is_int_value(term.arg(1)):
        divisor = term.arg(1).as_long()
        if divisor % modulus == 0:
            return _residue(term.arg(0), modulus, depth + 1, budget)
        return _residue(term.arg(0), divisor, depth + 1, budget) % divisor
    return term


def prove_modular_identity(left: z3.ExprRef, right: z3.ExprRef, *, deadline: float) -> bool:
    """Prove a universal identity over bounded atoms, or make no claim.

    Unsupported subterms become shared arbitrary integers of their unsigned
    width. Their real values are included. No caller premise is required, and
    an abstract counterexample is never returned as a concrete mismatch.
    """
    if not z3.is_bv(left) or not z3.is_bv(right) or left.size() != right.size():
        return False
    cache: dict[int, BoundedInteger] = {}
    constraints: list[z3.BoolRef] = []
    pending = [(left, False), (right, False)]
    visits = 0
    while pending:
        expression, ready = pending.pop()
        ident = expression.get_id()
        if ident in cache:
            continue
        visits += 1
        if visits > 8192 or time.monotonic() >= deadline:
            return False
        modulus = 1 << expression.size()
        if z3.is_bv_value(expression):
            value = expression.as_long()
            result = BoundedInteger(z3.IntVal(value), value, value)
        elif _admitted(expression):
            if not ready:
                pending.append((expression, True))
                pending.extend((child, False) for child in expression.children())
                continue
            result = _combine(expression, [cache[c.get_id()] for c in expression.children()])
            if result.high >= modulus:
                result = BoundedInteger(result.term % modulus, 0, modulus - 1)
        else:
            atom = z3.FreshInt("modular_scalar")
            constraints.extend((atom >= 0, atom < modulus))
            result = BoundedInteger(atom, 0, modulus - 1)
        cache[ident] = result
    return _prove_integers(cache[left.get_id()].term, cache[right.get_id()].term,
                           constraints, left.size(), deadline)


def _prove_integers(
    left: z3.ArithRef, right: z3.ArithRef, constraints: list[z3.BoolRef],
    width: int, deadline: float,
) -> bool:
    """Discharge the exact modular integer query within the original deadline."""
    modulus = 1 << width
    left_integer = _residue(z3.simplify(left), modulus) % modulus
    right_integer = _residue(z3.simplify(right), modulus) % modulus
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        return False
    solver = z3.SolverFor("QF_LIA")
    solver.set(timeout=remaining)
    solver.add(*constraints, left_integer != right_integer)
    return solver.check() == z3.unsat and time.monotonic() < deadline
