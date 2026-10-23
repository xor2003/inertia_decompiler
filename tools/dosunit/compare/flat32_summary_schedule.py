"""Build closed internal summaries from leaves under the caller's work budget.

Layer: dosunit call composition.
Responsibility: bypass recursive descent depth only by independently completed
generic summaries across direct calls and admitted tail transfers.
External/cyclic/unresolved-indirect graphs are never assumed closed.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from tools.dosunit.compare.flat32_call_contracts import (
    CallCompositionRefusal,
    InductiveLoopRequired,
    _check_compose_deadline,
    _ComposeSession,
)
from tools.dosunit.compare.flat32_call_lowering import _lift_function


def _children(session: _ComposeSession, address: int) -> set[int] | None:
    """Reject dependencies whose effects require an external or live context."""
    blocks = _lift_function(session, address)
    children: set[int] = set()
    for block in blocks.values():
        if (block.external_slot is not None
                or block.part.get("trap_exits") or "io" in block.part["outputs"]):
            return None
        children.update(block.tail_targets)
        if block.jumpkind == "Ijk_Call":
            if block.call_target is None:
                return None
            children.add(block.call_target)
    return children


def _postorder(session: _ComposeSession, entry: int, active: frozenset[int]) -> list[int] | None:
    """Find a bounded closed direct-call DAG without descending Python frames."""
    pending = [(entry, False)]
    visiting: set[int] = set()
    complete = set(session.summaries)
    order = []
    while pending:
        _check_compose_deadline(session.compose_stats)
        address, leaving = pending.pop()
        if leaving:
            visiting.remove(address)
            complete.add(address)
            order.append(address)
            continue
        if address in active or address in visiting:
            return None
        if address in complete:
            continue
        if len(visiting) + len(order) >= session.limits.max_inlined_calls - session.inlined_calls:
            return None
        if address not in session.functions:
            return None
        children = _children(session, address)
        if children is None:
            return None
        visiting.add(address)
        pending.append((address, True))
        pending.extend((child, False) for child in sorted(children, reverse=True))
    return order


def prepare_internal_summary(
    session: _ComposeSession, entry: int, active: frozenset[int],
    compose: Callable[..., dict[str, dict[str, Any]]],
) -> bool:
    """Reuse only actual generic compositions, never root-domain premises.

    Lifting, composition, calls and return checks charge the original session
    counters/deadline. Mode changes are local to construction and restored on
    every exit. Only complete bodies enter the existing summary cache.
    """
    if session.limits.max_inline_depth < 1:
        return False
    order = _postorder(session, entry, active)
    if order is None:
        return False
    root_bound, domain = session.root_bound_inputs, session.entry_domain
    session.root_bound_inputs, session.entry_domain = False, None
    try:
        for address in order:
            compose(session, address, frozenset({address}), 0)
    except InductiveLoopRequired:
        # Preserve the structural retry signal, never a generic countermodel.
        raise
    except CallCompositionRefusal:
        return False
    finally:
        session.root_bound_inputs, session.entry_domain = root_bound, domain
    return entry in session.summaries


def prepare_leaf_summary(
    session: _ComposeSession, entry: int,
    compose: Callable[..., dict[str, dict[str, Any]]],
) -> None:
    """Build a context-independent leaf once before substituting live caller state.

    Failed proposals consume the same work budget and fall back to contextual
    execution. Never cache a caller-bound state under an entry-only key. Leaves
    exclude calls, tail transfers, external effects, I/O and trap exits.
    """
    if entry in session.leaf_summary_attempts:
        return
    session.leaf_summary_attempts.add(entry)
    if _children(session, entry) != set():
        return
    root_bound, domain, buffers = session.root_bound_inputs, session.entry_domain, session.root_buffer_domains
    previous_frame = session.last_obligation_frame
    session.root_bound_inputs, session.entry_domain, session.root_buffer_domains = False, None, ()
    try:
        compose(session, entry, frozenset({entry}), 0)
    except CallCompositionRefusal:
        # A symbolic loop may require an actual caller bound. The original
        # contextual path still owns that proof; no failed summary is installed.
        session.last_obligation_frame = previous_frame
    finally:
        session.root_bound_inputs, session.entry_domain, session.root_buffer_domains = root_bound, domain, buffers
