"""Context-bound retries for a single flat32 loop-transition call.

Layer: dosunit relational loop proofs.
Responsibility: retry an unresolved nested callback using the live transition
state, without importing function-entry assumptions into arbitrary cutpoints.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from tools.dosunit.compare.flat32_call_contracts import (
    CallCompositionRefusal,
    _check_compose_deadline,
    _ComposeSession,
)


def compose_with_transition_context(
    session: _ComposeSession, attempt: Callable[[], dict[str, dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    """Retry once with contextual inputs; retain all consumed work budgets.

    The callback reads the session binding mode and supplies its actual state
    to the callee. Context-bound summaries never enter the generic cache.
    Restore the mode even on refusal, so another transition starts independently.
    Certificates from the abandoned generic attempt are not published.
    """
    if session.entry_domain is not None or session.external_bindings or session.root_entry is not None:
        raise CallCompositionRefusal("transition_cannot_assume_root_entry_domain")
    if session.root_bound_inputs:
        return attempt()
    records = (session.call_sites, session.tail_sites, session.constant_branch_proofs)
    lengths = tuple(len(items) for items in records)
    returns = session.return_targets_proved
    try:
        return attempt()
    except CallCompositionRefusal as error:
        if str(error) != "call_indirect_target_unconstrained":
            raise
    _check_compose_deadline(session.compose_stats)
    for items, length in zip(records, lengths, strict=True):
        del items[length:]
    session.return_targets_proved = returns
    session.root_bound_inputs = True
    try:
        result = attempt()
        for site in session.call_sites[lengths[0]:]:
            site["transition_context"] = True
        return result
    finally:
        session.root_bound_inputs = False
