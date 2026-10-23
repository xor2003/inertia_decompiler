"""Layer: dosunit relational loop proofs.

Responsibility: remove only lazy-flag outputs proved dead by a closed,
paired SSA dependency fixed point. Control, memory, I/O and return observations
remain exact; shared return-token components use the union of all obligations.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import (
    _check_compose_deadline,
    _initial_state,
    _register_widths,
    _term_nodes,
)
from tools.dosunit.ssa.composition import _abi_terms_equal, compose_block_outputs
from tools.dosunit.ssa.materialization import input_items
from tools.dosunit.ssa.ssa_constant_terms import constant_bitvector
from tools.dosunit.ssa.x86_flag_dependencies import flag_argument_demands

FLAGS: frozenset[str] = frozenset({"cc_op", "cc_dep1", "cc_dep2", "cc_ndep"})
REGISTERS: frozenset[str] = frozenset({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"})


@dataclass(frozen=True, slots=True)
class _FlagPair:
    """One paired transition's conservative dependency and successor union."""

    token: int
    terminal: bool
    successors: frozenset[int]
    dependencies: dict[str, frozenset[str]]
    obligation_dependencies: frozenset[str]


def _targets(term: dict[str, Any]) -> frozenset[int] | None:
    """Read every already-proved control-token leaf without pruning any arm."""
    pending = [term]
    result: set[int] = set()
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        literal = constant_bitvector(current)
        if literal is not None and literal[1] == 32:
            result.add(literal[0])
            continue
        args = current.get("args")
        if current.get("op") != "ite" or not isinstance(args, list) or len(args) != 3:
            return None
        if not isinstance(args[1], dict) or not isinstance(args[2], dict):
            return None
        pending.extend((args[1], args[2]))
    return frozenset(result)


def _state(function: dict[str, Any], deadline: float) -> dict[str, Any]:
    """Expand actual observed SSA outputs under arbitrary cutpoint inputs."""
    state = compose_block_outputs(function, function["outputs"], _initial_state(_register_widths()),
                                  compose_stats={"deadline": deadline})
    selected = {key: state[key] for key in function["outputs"]}
    if _term_nodes(selected, 50000) > 50000:
        raise S.LowerFailure("dead_flag_expression_limit", "flag dependency budget")
    return selected


def _flag_inputs(terms: list[dict[str, Any]], relocated: frozenset[int],
                 fields: frozenset[str]) -> frozenset[str]:
    """Collect flag inputs through only semantically demanded helper arguments."""
    pending = list(terms)
    seen: set[int] = set()
    names: set[str] = set()
    while pending:
        term = pending.pop()
        if id(term) in seen:
            continue
        seen.add(id(term))
        if term.get("op") == "input" and term.get("name") in fields:
            names.add(str(term["name"]))
        if _self_cancelling_value(term):
            continue
        demands = flag_argument_demands(term, relocated)
        pending.extend(term.get("args", []) if demands is None else
                       [argument for argument, bits in demands if bits > 0])
    return frozenset(names)


def _self_cancelling_value(term: dict[str, Any]) -> bool:
    """Only the value of same-width x-x/xor cancels, never separate flag state."""
    args = term.get("args")
    width = term.get("width")
    if (term.get("op") not in {"sub", "xor"} or type(width) is not int or width <= 0
            or not isinstance(args, list) or len(args) != 2):
        return False
    if any(not isinstance(arg, dict) or arg.get("width") != width for arg in args):
        return False
    return _abi_terms_equal(args[0], args[1], {}) is True


def _obligation_terms(function: dict[str, Any], deadline: float) -> list[dict[str, Any]]:
    """Resolve predicate assignment references before collecting dependencies."""
    predicates = {f"predicate_{index}": obligation["predicate"]
                  for index, obligation in enumerate(function.get("obligations", ()))
                  if isinstance(obligation.get("predicate"), dict)}
    if not predicates:
        return []
    return list(_state({**function, "outputs": predicates}, deadline).values())


def _pair(
    left: dict[str, Any], right: dict[str, Any], deadline: float, relocated: frozenset[int],
    fields: frozenset[str],
) -> _FlagPair | None:
    """Bind both sides to the same cutpoint token and merge all dependencies."""
    token = left["source"].get("cutpoint_token")
    if not isinstance(token, int) or token != right["source"].get("cutpoint_token"):
        return None
    terminal = left["source"]["jumpkind"] == "Ijk_Ret"
    if terminal != (right["source"]["jumpkind"] == "Ijk_Ret"):
        return None
    original, candidate = _state(left, deadline), _state(right, deadline)
    if original.keys() != candidate.keys() or (not terminal and not FLAGS.issubset(original)):
        return None
    dependencies = {
        key: _flag_inputs([original[key], candidate[key]], relocated, fields)
        for key in original
    }
    # Preconditions are observable proof requirements too. Never discard a
    # coordinate read only by an instruction's bound exception predicate.
    obligation_dependencies = _flag_inputs(
        [*_obligation_terms(left, deadline), *_obligation_terms(right, deadline)], relocated, fields,
    )
    targets = [frozenset()] if terminal else [_targets(state["eip"]) for state in (original, candidate)]
    if any(target is None for target in targets):
        return None
    successors = frozenset(value for target in targets if target is not None for value in target)
    return _FlagPair(token, terminal, successors, dependencies, obligation_dependencies)


def _required_outputs(pair: _FlagPair, live: dict[int, set[str]], fields: frozenset[str]) -> set[str]:
    """Keep all nonflags and all flags demanded by any possible successor."""
    required = set(pair.dependencies) - fields
    if pair.terminal:
        return set(pair.dependencies)
    for successor in pair.successors:
        required.update(live[successor])
    return required


def _fixed_point(pairs: list[_FlagPair], deadline: float, fields: frozenset[str]) -> dict[int, set[str]] | None:
    """Propagate paired input demands over every edge until no flag is added."""
    live: dict[int, set[str]] = {pair.token: set() for pair in pairs}
    if any(successor not in live for pair in pairs for successor in pair.successors):
        return None
    changed = True
    while changed:
        changed = False
        for pair in pairs:
            _check_compose_deadline({"deadline": deadline})
            required = _required_outputs(pair, live, fields)
            inputs = set(pair.obligation_dependencies).union(
                *(pair.dependencies[name] for name in required if name in pair.dependencies))
            if not inputs.issubset(live[pair.token]):
                live[pair.token].update(inputs)
                changed = True
    if any(not _required_outputs(pair, live, fields).issubset(pair.dependencies) for pair in pairs):
        return None
    return live


def _project(document: dict[str, Any], removed: list[set[str]]) -> dict[str, Any]:
    """Slice only proved-dead outputs; retain their definitions for other uses."""
    functions = []
    for function, dead in zip(document["functions"], removed, strict=True):
        outputs = {name: term for name, term in function["outputs"].items() if name not in dead}
        predicates = [o["predicate"] for o in function.get("obligations", ())
                      if isinstance(o.get("predicate"), dict)]
        functions.append({**function, "outputs": outputs,
                          "inputs": input_items([*outputs.values(), *predicates], function.get("assignments", []))})
    return {**document, "functions": functions}


def _dead_state_projection(
    oracle: dict[str, Any], candidate: dict[str, Any], *, deadline: float,
    fields: frozenset[str],
    candidate_normalization: Mapping[int, int] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Discharge dead-output admission over a complete closed transition set.

    Initial inputs remain identical. At every interior token the retained
    flags include every dependency of control, memory, I/O, nonflag registers,
    final observations and successor-live flags on either side. Thus induction
    needs no equality for removed fields. Returns are never projected.
    """
    originals, rebuilt = oracle["functions"], candidate["functions"]
    if not originals or len(originals) != len(rebuilt):
        return None
    try:
        relocated = frozenset(candidate_normalization or ())
        proposed = [_pair(left, right, deadline, relocated, fields)
                    for left, right in zip(originals, rebuilt, strict=True)]
        if any(pair is None for pair in proposed):
            return None
        pairs = [pair for pair in proposed if pair is not None]
        live = _fixed_point(pairs, deadline, fields)
    except S.LowerFailure:
        return None
    if live is None:
        return None
    removed = [(set(pair.dependencies) & fields) - _required_outputs(pair, live, fields) for pair in pairs]
    if not any(removed):
        return None
    evidence = {
        "method": "closed_paired_ssa_dependency_fixed_point",
        "removed_outputs": [{"transition": index, "fields": sorted(dead)}
                            for index, dead in enumerate(removed) if dead],
        "live_inputs": {str(token): sorted(fields) for token, fields in sorted(live.items())},
        "successors": [sorted(pair.successors) for pair in pairs],
        "return_observations_preserved": True,
        "exact_flag_helper_dependencies": True,
        "obligation_dependencies_preserved": True,
        "projectable_fields": sorted(fields),
    }
    return _project(oracle, removed), _project(candidate, removed), evidence


def dead_flag_projection(
    oracle: dict[str, Any], candidate: dict[str, Any], *, deadline: float,
    candidate_normalization: Mapping[int, int] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Remove only dead lazy flags, preserving every return observation."""
    return _dead_state_projection(oracle, candidate, deadline=deadline, fields=FLAGS,
                                  candidate_normalization=candidate_normalization)


def dead_register_projection(
    oracle: dict[str, Any], candidate: dict[str, Any], *, deadline: float,
    candidate_normalization: Mapping[int, int] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Keep only successor-live interior registers; all final outputs stay exact."""
    return _dead_state_projection(oracle, candidate, deadline=deadline, fields=FLAGS | REGISTERS,
                                  candidate_normalization=candidate_normalization)
