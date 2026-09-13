from __future__ import annotations

from dataclasses import replace

import pytest
from angr_platforms.X86_16.alias.register_reaching_source import (
    RegisterReachingSourceResult8616,
    RegisterReachingSourceVerdict8616,
)
from angr_platforms.X86_16.alias.terminal_pointer_output_contracts import (
    TerminalPointerAliasEvidence8616,
    TerminalPointerAliasFact8616,
    TerminalPointerAliasStats8616,
)
from angr_platforms.X86_16.callsite_summary import CallsitePushSourceKind8616
from angr_platforms.X86_16.ir import (
    AddressStatus,
    IRAddress,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.semantics.terminal_pointer_output_contracts import (
    TerminalPointerOutputDisposition8616,
    TerminalPointerOutputEvidence8616,
    TerminalPointerOutputFact8616,
    TerminalPointerOutputStats8616,
    TerminalPointerStoreSite8616,
)
from angr_platforms.X86_16.widening.terminal_pointer_output_contracts import (
    TerminalPointerOutputViewFailure8616,
)
from angr_platforms.X86_16.widening.terminal_pointer_output_views import (
    widen_terminal_pointer_output_views_8616,
)

FUNCTION = 0x1000
BP_VALUE = CallsitePushSourceKind8616.BP_VALUE.value
BYTE_LANES = 2


def _alias_fact(
    parameter_offset: int,
    relative_offset: int,
    width: int,
    *,
    base_version: int = 1,
    disposition: TerminalPointerOutputDisposition8616 = (
        TerminalPointerOutputDisposition8616.MUST_WRITE
    ),
    terminals: tuple[int, ...] = (FUNCTION,),
    definite: tuple[int, ...] = (FUNCTION,),
    store_block: int = FUNCTION,
) -> TerminalPointerAliasFact8616:
    base = IRValue(MemSpace.REG, name="bx", size=2, version=base_version)
    address = IRAddress(
        MemSpace.DS,
        base=("bx",),
        offset=relative_offset,
        size=width,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
        base_values=(base,),
    )
    output = TerminalPointerOutputFact8616(
        address,
        base,
        disposition,
        (TerminalPointerStoreSite8616(store_block, 0, store_block),),
        terminals,
        definite,
    )
    parameter = IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=parameter_offset,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )
    source = RegisterReachingSourceResult8616(
        RegisterReachingSourceVerdict8616.PROVEN,
        (BP_VALUE, parameter_offset, 2),
        1,
        1,
        1,
        1,
        0,
    )
    return TerminalPointerAliasFact8616(output, parameter, (source,))


def _evidence(
    *facts: TerminalPointerAliasFact8616,
) -> TerminalPointerAliasEvidence8616:
    count = len(facts)
    terminal = TerminalPointerOutputEvidence8616(
        FUNCTION,
        tuple(fact.terminal_output for fact in facts),
        None,
        TerminalPointerOutputStats8616(count, count, count, count),
    )
    return TerminalPointerAliasEvidence8616(
        FUNCTION,
        facts,
        None,
        TerminalPointerAliasStats8616(count, count, count, count),
        terminal,
    )


def test_contiguous_byte_lanes_form_one_word_view() -> None:
    evidence = widen_terminal_pointer_output_views_8616(
        _evidence(_alias_fact(4, 0, 1), _alias_fact(4, 1, 1, base_version=2))
    )

    assert evidence.complete
    assert evidence.stats.raw_fact_count == BYTE_LANES
    assert evidence.stats.materialized_count == 1
    assert len(evidence.facts) == 1
    assert (evidence.facts[0].relative_offset, evidence.facts[0].width) == (0, 2)
    assert len(evidence.facts[0].alias_outputs) == BYTE_LANES


def test_gap_and_distinct_parameters_remain_separate_views() -> None:
    evidence = widen_terminal_pointer_output_views_8616(
        _evidence(
            _alias_fact(4, 0, 1),
            _alias_fact(4, 2, 1, base_version=2),
            _alias_fact(6, 0, 1, base_version=3),
        )
    )

    assert evidence.complete
    expected_views = {(4, 0, 1), (4, 2, 1), (6, 0, 1)}
    assert len(evidence.facts) == len(expected_views)
    assert {
        (fact.parameter_storage.offset, fact.relative_offset, fact.width)
        for fact in evidence.facts
    } == expected_views


def test_adjacent_lanes_with_distinct_path_coverage_remain_separate() -> None:
    conditional = _alias_fact(
        4,
        1,
        1,
        base_version=2,
        disposition=TerminalPointerOutputDisposition8616.CONDITIONAL,
        terminals=(0x1010, 0x1020),
        definite=(0x1010,),
    )
    evidence = widen_terminal_pointer_output_views_8616(
        _evidence(_alias_fact(4, 0, 1), conditional)
    )

    assert evidence.complete
    assert len(evidence.facts) == BYTE_LANES


def test_overlapping_ranges_with_distinct_path_coverage_refuse_atomically() -> None:
    conditional = _alias_fact(
        4,
        1,
        1,
        base_version=2,
        disposition=TerminalPointerOutputDisposition8616.CONDITIONAL,
        terminals=(0x1010, 0x1020),
        definite=(0x1010,),
    )
    evidence = widen_terminal_pointer_output_views_8616(
        _evidence(_alias_fact(4, 0, 2), conditional)
    )

    assert not evidence.complete
    assert evidence.facts == ()
    assert (
        evidence.failure
        is TerminalPointerOutputViewFailure8616.OVERLAPPING_PATH_CONFLICT
    )


def test_duplicate_exact_output_refuses_atomically() -> None:
    fact = _alias_fact(4, 0, 1)
    evidence = widen_terminal_pointer_output_views_8616(_evidence(fact, fact))

    assert not evidence.complete
    assert evidence.facts == ()
    assert evidence.failure is TerminalPointerOutputViewFailure8616.DUPLICATE_OUTPUT


@pytest.mark.parametrize("same_write_block", [False, True])
def test_shared_return_does_not_prove_conditional_lanes_cooccur(same_write_block: bool) -> None:
    """Only co-located conditional stores may share a path-qualified view."""
    first_block = FUNCTION + 0x10
    second_block = first_block if same_write_block else FUNCTION + 0x20
    facts = tuple(
        _alias_fact(
            4, offset, 1,
            disposition=TerminalPointerOutputDisposition8616.CONDITIONAL,
            terminals=(FUNCTION + 0x30,), definite=(), store_block=block,
        )
        for offset, block in enumerate((first_block, second_block))
    )
    result = widen_terminal_pointer_output_views_8616(_evidence(*facts))

    assert result.complete
    expected_views = 1 if same_write_block else BYTE_LANES
    assert len(result.facts) == expected_views
    if same_write_block:
        assert result.facts[0].width == BYTE_LANES
    else:
        assert all(view.width == 1 for view in result.facts)
        forged = replace(result.facts[0], width=BYTE_LANES, alias_outputs=facts)
        assert not forged.complete
