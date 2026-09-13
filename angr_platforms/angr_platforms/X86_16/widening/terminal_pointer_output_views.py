"""Widen Alias-owned pointer outputs into exact contiguous byte views.

Layer: Widening.
Responsibility: group touching or overlapping output lanes only when Alias
ownership and terminal-path coverage agree.
Conditional lanes additionally require matching store-block evidence; a shared
return alone does not prove coexecution. This module does not inspect CFGs,
recover aliases, infer pointee types, bind caller targets, mutate prototypes,
or render C. Disjoint ranges remain distinct views.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from ..alias.terminal_pointer_output_contracts import (
    TerminalPointerAliasEvidence8616,
    TerminalPointerAliasFact8616,
)
from ..ir import IRAddress, MemSpace
from ..semantics.terminal_pointer_output_contracts import (
    TerminalPointerOutputDisposition8616,
)
from .terminal_pointer_output_contracts import (
    TerminalPointerOutputViewEvidence8616,
    TerminalPointerOutputViewFact8616,
    TerminalPointerOutputViewFailure8616,
    TerminalPointerOutputViewStats8616,
)

type _OwnerKey8616 = tuple[IRAddress, MemSpace]
type _CoverageKey8616 = tuple[
    TerminalPointerOutputDisposition8616,
    tuple[int, ...],
    tuple[int, ...],
    tuple[int, ...],
]


def _refused_8616(
    evidence: TerminalPointerAliasEvidence8616,
    failure: TerminalPointerOutputViewFailure8616,
    normalized_count: int = 0,
) -> TerminalPointerOutputViewEvidence8616:
    """Build one atomic Widening refusal without publishing partial views."""
    raw_count = max(1, evidence.stats.raw_fact_count, len(evidence.facts))
    return TerminalPointerOutputViewEvidence8616(
        evidence.function_addr,
        (),
        failure,
        TerminalPointerOutputViewStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            failure_count=1,
        ),
        evidence,
    )


def _owner_key_8616(fact: TerminalPointerAliasFact8616) -> _OwnerKey8616:
    """Return the exact parameter and segmented-space owner identity."""
    return fact.parameter_storage, fact.terminal_output.segment


def _coverage_key_8616(fact: TerminalPointerAliasFact8616) -> _CoverageKey8616:
    """Return immutable terminal-path coverage for one output lane."""
    output = fact.terminal_output
    return (
        output.disposition,
        output.terminal_block_addrs,
        output.definitely_written_terminal_block_addrs,
        output.conditional_store_blocks,
    )


def _interval_8616(fact: TerminalPointerAliasFact8616) -> tuple[int, int]:
    """Return the exact relative half-open byte range of one Alias fact."""
    output = fact.terminal_output
    return output.relative_offset, output.relative_offset + output.width


def _fact_order_8616(
    fact: TerminalPointerAliasFact8616,
) -> tuple[int, str, int, int, int]:
    """Return deterministic parameter, register-version, and range ordering."""
    output = fact.terminal_output
    register = output.base_register
    version = output.base_version
    if register is None or version is None:
        raise ValueError("complete pointer Alias fact lost versioned base identity")
    return (
        int(fact.parameter_storage.offset),
        register,
        version,
        output.relative_offset,
        output.width,
    )


def _paths_conflict_8616(
    facts: Iterable[TerminalPointerAliasFact8616],
) -> bool:
    """Return whether overlapping owner ranges carry incompatible coverage."""
    by_owner: dict[_OwnerKey8616, list[TerminalPointerAliasFact8616]] = defaultdict(list)
    for fact in facts:
        by_owner[_owner_key_8616(fact)].append(fact)
    for owned in by_owner.values():
        ordered = sorted(owned, key=_fact_order_8616)
        for index, left in enumerate(ordered):
            left_start, left_end = _interval_8616(left)
            for right in ordered[index + 1 :]:
                right_start, right_end = _interval_8616(right)
                if right_start >= left_end or left_start >= right_end:
                    continue
                if _coverage_key_8616(left) != _coverage_key_8616(right):
                    return True
    return False


def _build_view_8616(
    owner: _OwnerKey8616,
    coverage: _CoverageKey8616,
    facts: list[TerminalPointerAliasFact8616],
) -> TerminalPointerOutputViewFact8616:
    """Build one contiguous view from already compatible ordered lanes."""
    starts_and_ends = tuple(_interval_8616(fact) for fact in facts)
    start = min(interval[0] for interval in starts_and_ends)
    end = max(interval[1] for interval in starts_and_ends)
    return TerminalPointerOutputViewFact8616(
        parameter_storage=owner[0],
        segment=owner[1],
        relative_offset=start,
        width=end - start,
        disposition=coverage[0],
        terminal_block_addrs=coverage[1],
        definitely_written_terminal_block_addrs=coverage[2],
        alias_outputs=tuple(facts),
    )


def widen_terminal_pointer_output_views_8616(
    evidence: TerminalPointerAliasEvidence8616,
) -> TerminalPointerOutputViewEvidence8616:
    """Group exact Alias facts into deterministic gap-free pointer views."""
    if not evidence.complete:
        return _refused_8616(
            evidence,
            TerminalPointerOutputViewFailure8616.ALIAS_EVIDENCE_REFUSED,
        )
    if any(not fact.complete for fact in evidence.facts):
        return _refused_8616(
            evidence,
            TerminalPointerOutputViewFailure8616.OUTPUT_INCOMPLETE,
        )
    identities = tuple(
        (_owner_key_8616(fact), fact.terminal_output.key)
        for fact in evidence.facts
    )
    if len(set(identities)) != len(identities):
        return _refused_8616(
            evidence,
            TerminalPointerOutputViewFailure8616.DUPLICATE_OUTPUT,
        )
    if _paths_conflict_8616(evidence.facts):
        return _refused_8616(
            evidence,
            TerminalPointerOutputViewFailure8616.OVERLAPPING_PATH_CONFLICT,
        )

    grouped: dict[
        tuple[_OwnerKey8616, _CoverageKey8616],
        list[TerminalPointerAliasFact8616],
    ] = defaultdict(list)
    for fact in evidence.facts:
        grouped[(_owner_key_8616(fact), _coverage_key_8616(fact))].append(fact)

    views: list[TerminalPointerOutputViewFact8616] = []
    for (owner, coverage), facts in sorted(
        grouped.items(),
        key=lambda item: (
            int(item[0][0][0].offset),
            item[0][0][1].value,
            item[0][1][0].value,
            item[0][1][1],
            item[0][1][2],
        ),
    ):
        ordered = sorted(facts, key=_fact_order_8616)
        component = [ordered[0]]
        component_end = _interval_8616(ordered[0])[1]
        for fact in ordered[1:]:
            start, end = _interval_8616(fact)
            if start > component_end:
                views.append(_build_view_8616(owner, coverage, component))
                component = [fact]
                component_end = end
                continue
            component.append(fact)
            component_end = max(component_end, end)
        views.append(_build_view_8616(owner, coverage, component))

    count = len(views)
    result = TerminalPointerOutputViewEvidence8616(
        evidence.function_addr,
        tuple(views),
        None,
        TerminalPointerOutputViewStats8616(len(evidence.facts), count, count, count),
        evidence,
    )
    if not result.complete:
        raise RuntimeError("terminal pointer Widening accounting did not close")
    return result


__all__ = ["widen_terminal_pointer_output_views_8616"]
