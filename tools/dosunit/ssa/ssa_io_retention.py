"""Reachability receipts for materialized ordered I/O state.

Layer: dosunit SSA evidence.
Responsibility: recover only events in the final ordered state predecessor
chain, resolving owned materialized references without decoding or solving.
"""
from __future__ import annotations

from collections.abc import Mapping


def _assignment_index(assignments: list[object]) -> dict[str, dict[str, object]] | None:
    """Index named definitions; duplicate or malformed identities refuse."""
    definitions: dict[str, dict[str, object]] = {}
    for term in assignments:
        if not isinstance(term, dict):
            return None
        identity = term.get("id")
        if identity is None:
            continue
        if not isinstance(identity, str) or identity in definitions:
            return None
        definitions[identity] = term
    return definitions


def _resolve_term(
    term: object, definitions: Mapping[str, dict[str, object]],
) -> dict[str, object] | None:
    """Resolve reference aliases with explicit missing/cyclic-ref rejection."""
    seen: set[str] = set()
    while isinstance(term, dict) and "ref" in term:
        reference = term["ref"]
        if len(term) != 1 or not isinstance(reference, str) or reference in seen:
            return None
        seen.add(reference)
        term = definitions.get(reference)
    return term if isinstance(term, dict) else None


def _state_event(
    state: dict[str, object], definitions: Mapping[str, dict[str, object]],
) -> tuple[dict[str, object], object] | None:
    """Recover one state transition and its predecessor, including dead reads."""
    args = state.get("args")
    if not isinstance(args, list) or len(args) != 5:
        return None
    if state.get("op") == "summary_io_out":
        return state, args[0]
    if state.get("op") != "summary_io_in_state":
        return None
    read = _resolve_term(args[4], definitions)
    if read is None or read.get("op") != "summary_io_in":
        return None
    # The state must retain the same sampled read: predecessor, index, port,
    # and width. The lowerer materializes shared children with equal refs.
    if read.get("args") != args[:4]:
        return None
    return read, args[0]


def retained_io_event_terms(
    assignments: list[object], final_state: object,
) -> tuple[dict[str, object], ...] | None:
    """Return chronological events reachable through final ordered I/O state.

    Events reachable only as value computations or unused assignments do not
    count. Every predecessor must be a modeled transition or the initial io
    input. Missing references, state cycles, and malformed read-state links
    return no receipt, never a partial event sequence.
    """
    definitions = _assignment_index(assignments)
    if definitions is None:
        return None
    events: list[dict[str, object]] = []
    seen: set[int] = set()
    current = final_state
    while True:
        state = _resolve_term(current, definitions)
        if state is None or id(state) in seen:
            return None
        seen.add(id(state))
        if state.get("op") == "mem_input" and state.get("name") == "io":
            return tuple(reversed(events))
        transition = _state_event(state, definitions)
        if transition is None:
            return None
        event, current = transition
        events.append(event)
