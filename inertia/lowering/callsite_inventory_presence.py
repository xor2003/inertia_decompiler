"""Account for exact machine callsites represented by a structured C tree.

Layer: Types/Lowering.
Responsibility: combine exact call tags with live node-to-summary bindings into
the represented subset of an authoritative typed callsite inventory.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

This module neither discovers calls nor compares rendered callee names. Missing
call materialization may consume its result, while Structuring only sequences
that consumer and Rewrite or CLI may provide compatibility fallback only.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, cast

from inertia.semantics.callsite_summary import CallsiteSummary8616, structured_callsite_addr_8616

__all__ = ["represented_callsite_addrs_8616"]


def represented_callsite_addrs_8616(
    call_nodes: Iterable[object],
    attached_summaries: object | None,
) -> frozenset[int]:
    """Return exact callsites represented by live structured call nodes."""
    nodes = tuple(call_nodes)
    represented = {
        callsite_addr
        for node in nodes
        if isinstance(
            (callsite_addr := structured_callsite_addr_8616(cast(Any, node))),
            int,
        )
    }
    if attached_summaries is None:
        return frozenset(represented)
    if not isinstance(attached_summaries, Mapping):
        raise TypeError("callsite summary carrier must be a mapping")
    live_node_ids = {id(node) for node in nodes}
    for node_id, summary in attached_summaries.items():
        if not isinstance(node_id, int) or not isinstance(summary, CallsiteSummary8616):
            raise TypeError("callsite summary carrier contains an invalid owned contract")
        if node_id in live_node_ids:
            represented.add(summary.callsite_addr)
    return frozenset(represented)
