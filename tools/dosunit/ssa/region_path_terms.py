"""Shared arch-neutral SSA term helpers for staged macro-step paths.

Layer: dosunit relational path terms.
Responsibility: provide the small typed term algebra both width adapters use:
width-1 guard connectives, frontier join-guard extraction over the same
const/ite control shapes ``_destinations`` already admits, masked full-state
outputs with shared sentinels, and per-side endpoint-consistency terms. These
helpers never normalize control destinations: an unpaired or symbolic head is
reported to the caller, which refuses with a typed reason.
"""

from __future__ import annotations

from typing import Any

from tools.dosunit.compare.macro_step_contracts import MacroStepReason, MacroStepRefusal
from tools.dosunit.ssa.ssa_constant_terms import constant_bitvector

type Term = dict[str, Any]

SENTINEL_MEM_NAME = "macro_sentinel_mem"
SENTINEL_IO_NAME = "macro_sentinel_io"


def const_term(value: int, width: int) -> Term:
    """Publish a literal bitvector term with its exact width."""
    return {"op": "const", "width": width, "value": hex(value)}


def guard_true() -> Term:
    """Width-1 true guard term."""
    return const_term(1, 1)


def guard_false() -> Term:
    """Width-1 false guard term."""
    return const_term(0, 1)


def guard_not(term: Term) -> Term:
    """Width-1 negation; folds literal constants."""
    literal = constant_bitvector(term)
    if literal is not None:
        return guard_false() if literal[0] else guard_true()
    return {"op": "not", "width": 1, "args": [term]}


def guard_and(left: Term, right: Term) -> Term:
    """Width-1 conjunction; folds neutral/absorbing literals."""
    left_lit, right_lit = constant_bitvector(left), constant_bitvector(right)
    if left_lit is not None:
        return right if left_lit[0] else guard_false()
    if right_lit is not None:
        return left if right_lit[0] else guard_false()
    if left is right or left == right:
        return left
    return {"op": "and", "width": 1, "args": [left, right]}


def guard_or(left: Term, right: Term) -> Term:
    """Width-1 disjunction; folds neutral/absorbing literals."""
    left_lit, right_lit = constant_bitvector(left), constant_bitvector(right)
    if left_lit is not None:
        return guard_true() if left_lit[0] else right
    if right_lit is not None:
        return guard_true() if right_lit[0] else left
    if left is right or left == right:
        return left
    return {"op": "or", "width": 1, "args": [left, right]}


def guard_eq(left: Term, right: Term) -> Term:
    """Width-1 equality predicate between two same-width terms."""
    return {"op": "eq", "width": 1, "args": [left, right]}


def guard_implies(condition: Term, conclusion: Term) -> Term:
    """Width-1 ``condition -> conclusion`` as an or-term."""
    return guard_or(guard_not(condition), conclusion)


def path_guard_term(control_term: Term, endpoint_marker: int) -> Term | None:
    """Select-condition under which a control term resolves to a marker.

    Walks only const/ite control shapes, mirroring ``_destinations`` in the
    production transitions: ``ite(c, a, b)`` selects the marker under
    ``c`` on the true side and ``not c`` on the false side, recursively.
    Returns ``None`` when any arm is not a literal destination — callers must
    translate that into ``MACRO_GUARD_UNRESOLVED``; no symbolic destination is
    guessed. The returned term is width-1.
    """
    literal = constant_bitvector(control_term)
    if literal is not None:
        return guard_true() if literal[0] == endpoint_marker else guard_false()
    args = control_term.get("args")
    if control_term.get("op") != "ite" or not isinstance(args, list) or len(args) != 3:
        return None
    if not all(isinstance(arg, dict) for arg in args):
        return None
    condition, if_true, if_false = args
    cond_lit = constant_bitvector(condition)
    if cond_lit is not None:
        return path_guard_term(if_true if cond_lit[0] else if_false, endpoint_marker)
    true_guard = path_guard_term(if_true, endpoint_marker)
    false_guard = path_guard_term(if_false, endpoint_marker)
    if true_guard is None or false_guard is None:
        return None
    return guard_or(guard_and(condition, true_guard), guard_and(guard_not(condition), false_guard))


def scalar_sentinel(term: Term) -> Term:
    """Shared const-0 sentinel at the exact width of the masked term."""
    width = term.get("width")
    if type(width) is not int or width <= 0:
        raise MacroStepRefusal(MacroStepReason.MACRO_ADMISSION, {"invalid_scalar_width": width})
    return const_term(0, width)


def memory_sentinel(name: str = SENTINEL_MEM_NAME) -> Term:
    """Shared fresh memory leaf so masked memory compares stay whole-domain."""
    return {"op": "mem_input", "name": name, "addr_width": 32, "value_width": 8}


def io_sentinel(name: str = SENTINEL_IO_NAME) -> Term:
    """Shared fresh I/O leaf used identically on both compared sides."""
    return {"op": "mem_input", "name": name, "addr_width": 32, "value_width": 8}


def _sentinel_for(name: str, term: Term) -> Term:
    """Name-keyed shared sentinel: memory/io leaves, scalars const-0."""
    if name == "memory":
        return memory_sentinel()
    if name == "io":
        return io_sentinel()
    return scalar_sentinel(term)


def masked_term(term: Term, guard: Term, *, name: str) -> Term:
    """``ite(guard, term, shared_sentinel)`` preserving sort and width."""
    sentinel = _sentinel_for(name, term)
    width = term.get("width", 0)
    return {"op": "ite", "width": width, "args": [guard, term, sentinel]}


def masked_state(
    state: dict[str, Term], guard: Term, *, drop_names: frozenset[str] = frozenset(),
) -> dict[str, Term]:
    """Mask every observable of a composed state under its path guard.

    Every name keeps the same sort on both sides: memory and io use the shared
    leaves, every scalar uses the width-matched const-0 sentinel. No unrelated
    data or control output is projected away; callers drop only the explicit
    paired-control fields their lane replaces with the endpoint obligation.
    """
    masked: dict[str, Term] = {}
    for name, term in state.items():
        if not isinstance(term, dict):
            raise MacroStepRefusal(MacroStepReason.MACRO_ADMISSION, {"invalid_state_term": name})
        if name in drop_names:
            continue
        masked[str(name)] = masked_term(term, guard, name=str(name))
    return masked


def endpoint_consistency_term(
    control_term: Term, endpoint_marker: int, guard: Term, *,
    control_width: int = 32, extra_predicates: tuple[Term, ...] = (),
) -> Term:
    """Width-1 ``guard -> (control == marker and extras)`` discharge term.

    The marker is the actual recorded identity (physical head on real16, the
    lane token on flat32). Any arm not reaching the marker makes the term
    falsifiable; symbolic control cannot be coerced.
    """
    equality = guard_eq(control_term, const_term(endpoint_marker, control_width))
    for predicate in extra_predicates:
        equality = guard_and(equality, predicate)
    return guard_implies(guard, equality)
