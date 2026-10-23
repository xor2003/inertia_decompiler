"""Widening regressions for the named logical pair-type contract."""

from __future__ import annotations

from dataclasses import replace

import pytest

from inertia.alias.carry_borrow_projection import project_carry_borrow_aliases_8616
from inertia.ir import MemSpace
from inertia.semantics.carry_borrow_contracts import CarryBorrowKind8616
from inertia.semantics.carry_borrow_links import analyze_carry_borrow_links_8616
from inertia.widening.carry_borrow_values import (
    WideCarryBorrowValue8616,
    WideRegisterSlice8616,
    WideValueSignedness8616,
    widen_carry_borrow_values_8616,
)
from inertia.widening.pair_type_contracts import (
    WidePairEvidence8616,
    WidePairIllegality8616,
    WidePairOrder8616,
    WidePairState8616,
    materialize_wide_pair_evidence_8616,
    wide_pair_type_name_8616,
    wide_pair_value_consistent_8616,
)
from tests.fixtures.x86_16_carry_borrow_call_output_support import lift_after_dx_ax_call

pytestmark = pytest.mark.decompiler


def _wide_value(code: bytes) -> WideCarryBorrowValue8616:
    """Lift, link, alias, and widen one proven carry/borrow pair."""
    function_ssa = lift_after_dx_ax_call(code=code)
    semantics = analyze_carry_borrow_links_8616(function_ssa)
    aliases = project_carry_borrow_aliases_8616(semantics, function_ssa)
    widening = widen_carry_borrow_values_8616(aliases)
    assert widening.complete and widening.stats.materialized_count == 1
    return widening.values[0]


def test_proven_value_retains_named_pair_contract() -> None:
    """A proven wide value owns one named pair with combine legality."""
    value = _wide_value(bytes.fromhex("01 d8 11 ca c3"))

    pair = value.pair
    assert pair.state is WidePairState8616.PAIRED
    assert pair.combine_authorized and pair.split_authorized
    assert pair.illegality is None
    pair_type = pair.type
    assert pair_type.name == "wide_pair32"
    assert pair.kind is CarryBorrowKind8616.ADD_WITH_CARRY
    assert pair_type.signedness is WideValueSignedness8616.UNKNOWN
    assert (pair_type.total_size, pair_type.low_size, pair_type.high_size) == (4, 2, 2)
    assert pair.address_space is None
    assert pair.ordered_halves == (pair.low, pair.high)
    assert pair.low.order is WidePairOrder8616.LOW
    assert pair.high.order is WidePairOrder8616.HIGH
    assert pair.low.slice is value.low and pair.high.slice is value.high
    assert (pair.low.result.name, pair.high.result.name) == ("ax", "dx")
    assert pair.low.domain != pair.high.domain
    assert pair.low.result.version == value.low.result.version
    assert pair.high.result.version == value.high.result.version
    assert wide_pair_value_consistent_8616(value) is None
    assert wide_pair_type_name_8616(4) == "wide_pair32"


def test_borrow_value_retains_the_same_named_pair_type() -> None:
    """Type identity is width/layout/signedness; kind stays on the evidence."""
    value = _wide_value(bytes.fromhex("29 d8 19 ca c3"))

    assert value.pair.kind is CarryBorrowKind8616.SUB_WITH_BORROW
    assert value.pair.type.name == "wide_pair32"
    assert value.pair.state is WidePairState8616.PAIRED
    assert wide_pair_value_consistent_8616(value) is None


def test_pair_contract_preserves_segmented_source_space() -> None:
    """A named pair is not a flat pointer; the DS source space survives."""
    value = _wide_value(bytes.fromhex("03 06 00 20 13 16 02 20 c3"))

    assert value.source_memory is not None
    assert value.source_memory.space is MemSpace.DS
    assert value.pair.address_space is MemSpace.DS
    assert value.pair.type.name == "wide_pair32"
    assert wide_pair_value_consistent_8616(value) is None


def _pair_for(
    value: WideCarryBorrowValue8616,
    *,
    low: WideRegisterSlice8616 | None = None,
    high: WideRegisterSlice8616 | None = None,
    claimed_size: int = 4,
) -> WidePairEvidence8616:
    """Build pair evidence from one value's slices with optional overrides."""
    return materialize_wide_pair_evidence_8616(
        kind=CarryBorrowKind8616.ADD_WITH_CARRY,
        claimed_size=claimed_size,
        signedness=WideValueSignedness8616.UNKNOWN,
        address_space=None,
        low=value.low if low is None else low,
        high=value.high if high is None else high,
    )


@pytest.mark.parametrize(
    ("mutate", "expected"),
    (
        pytest.param(
            lambda value: _pair_for(value, high=value.low),
            WidePairIllegality8616.HALF_IDENTITY_MISMATCH,
            id="duplicated-half",
        ),
        pytest.param(
            lambda value: _pair_for(value, claimed_size=8),
            WidePairIllegality8616.TOTAL_WIDTH_MISMATCH,
            id="overclaimed-total",
        ),
        pytest.param(
            lambda value: _pair_for(
                value,
                high=replace(value.high, result=replace(value.high.result, space=MemSpace.DS)),
            ),
            WidePairIllegality8616.HALF_STORAGE_MISMATCH,
            id="foreign-space-half",
        ),
        pytest.param(
            lambda value: _pair_for(
                value,
                high=replace(value.high, result=replace(value.high.result, size=1)),
            ),
            WidePairIllegality8616.HALF_WIDTH_MISMATCH,
            id="byte-half",
        ),
        pytest.param(
            lambda value: _pair_for(
                value,
                high=replace(value.high, result_domain=value.low.result_domain),
            ),
            WidePairIllegality8616.HALF_DOMAIN_COLLISION,
            id="domain-collision",
        ),
    ),
)
def test_pair_materialization_refuses_incoherent_halves(mutate, expected) -> None:
    """Malformed halves produce UNPAIRED evidence, never combine legality."""
    value = _wide_value(bytes.fromhex("01 d8 11 ca c3"))

    pair = mutate(value)

    assert pair.state is WidePairState8616.UNPAIRED
    assert pair.illegality is expected
    assert not pair.combine_authorized
    assert not pair.split_authorized


@pytest.mark.parametrize(
    ("mutate", "expected"),
    (
        pytest.param(
            lambda value: replace(value, size=2),
            WidePairIllegality8616.VALUE_WIDTH_MISMATCH,
            id="shrunk-total",
        ),
        pytest.param(
            lambda value: replace(value, kind=CarryBorrowKind8616.SUB_WITH_BORROW),
            WidePairIllegality8616.KIND_MISMATCH,
            id="kind",
        ),
        pytest.param(
            lambda value: replace(value, address_space=MemSpace.DS),
            WidePairIllegality8616.SOURCE_SPACE_MISMATCH,
            id="claimed-space",
        ),
        pytest.param(
            lambda value: replace(
                value,
                low=replace(value.low, result=replace(value.low.result, size=1)),
            ),
            WidePairIllegality8616.HALF_IDENTITY_MISMATCH,
            id="shrunk-low-half",
        ),
        pytest.param(
            lambda value: replace(value, low=value.high, high=value.low),
            WidePairIllegality8616.HALF_IDENTITY_MISMATCH,
            id="swapped-halves",
        ),
        pytest.param(
            lambda value: replace(
                value,
                high=replace(
                    value.high, result=replace(value.high.result, name="si")
                ),
            ),
            WidePairIllegality8616.HALF_IDENTITY_MISMATCH,
            id="foreign-half",
        ),
        pytest.param(
            lambda value: replace(value, pair=None),
            WidePairIllegality8616.PAIR_EVIDENCE_MISSING,
            id="missing-pair",
        ),
        pytest.param(
            lambda value: replace(
                value, pair=replace(value.pair, state=WidePairState8616.UNPAIRED)
            ),
            WidePairIllegality8616.COMBINE_NOT_AUTHORIZED,
            id="unpaired-state",
        ),
        pytest.param(
            lambda value: replace(
                value, pair=replace(value.pair, state=WidePairState8616.SPLIT)
            ),
            WidePairIllegality8616.COMBINE_NOT_AUTHORIZED,
            id="split-state",
        ),
        pytest.param(
            lambda value: replace(
                value,
                pair=replace(
                    value.pair, type=replace(value.pair.type, low_size=1)
                ),
            ),
            WidePairIllegality8616.TYPE_WIDTH_MISMATCH,
            id="forged-low-width",
        ),
        pytest.param(
            lambda value: replace(
                value,
                pair=replace(
                    value.pair, type=replace(value.pair.type, name="forged")
                ),
            ),
            WidePairIllegality8616.TYPE_NAME_MISMATCH,
            id="forged-name",
        ),
        pytest.param(
            lambda value: replace(
                value,
                pair=replace(
                    value.pair,
                    low=replace(value.pair.low, order=WidePairOrder8616.HIGH),
                ),
            ),
            WidePairIllegality8616.HALF_ORDER_MISMATCH,
            id="forged-order",
        ),
        pytest.param(
            lambda value: replace(
                value,
                pair=replace(
                    value.pair,
                    illegality=WidePairIllegality8616.HALF_WIDTH_MISMATCH,
                ),
            ),
            WidePairIllegality8616.HALF_WIDTH_MISMATCH,
            id="contradictory-illegality",
        ),
        pytest.param(
            lambda value: replace(
                value,
                pair=replace(
                    value.pair,
                    low=replace(
                        value.pair.low,
                        slice=replace(
                            value.pair.low.slice,
                            result=replace(value.pair.low.result, size=1),
                        ),
                    ),
                    high=replace(
                        value.pair.high,
                        slice=replace(
                            value.pair.high.slice,
                            result=replace(value.pair.high.result, size=3),
                        ),
                    ),
                    type=replace(value.pair.type, low_size=1, high_size=3),
                ),
            ),
            WidePairIllegality8616.HALF_WIDTH_MISMATCH,
            id="unequal-coherent-halves",
        ),
        pytest.param(
            lambda value: replace(
                value,
                pair=replace(
                    value.pair,
                    low=replace(
                        value.pair.low,
                        slice=replace(
                            value.pair.low.slice,
                            result=replace(
                                value.pair.low.result, space=MemSpace.SS
                            ),
                        ),
                    ),
                ),
            ),
            WidePairIllegality8616.HALF_STORAGE_MISMATCH,
            id="nonregister-half",
        ),
    ),
)
def test_value_consistency_reports_typed_illegality(mutate, expected) -> None:
    """Corrupted or forged pair evidence reports a typed refusal reason."""
    value = _wide_value(bytes.fromhex("01 d8 11 ca c3"))

    assert wide_pair_value_consistent_8616(mutate(value)) is expected
    assert wide_pair_value_consistent_8616(value) is None


def test_split_state_authorizes_halves_but_never_combine() -> None:
    """SPLIT legality keeps halves consumable without a combine grant."""
    value = _wide_value(bytes.fromhex("01 d8 11 ca c3"))

    split = replace(value.pair, state=WidePairState8616.SPLIT)
    assert not split.combine_authorized
    assert split.split_authorized
    unpaired = replace(value.pair, state=WidePairState8616.UNPAIRED)
    assert not unpaired.combine_authorized
    assert not unpaired.split_authorized
    contradictory = replace(
        value.pair, illegality=WidePairIllegality8616.HALF_WIDTH_MISMATCH
    )
    assert not contradictory.combine_authorized
    assert not contradictory.split_authorized


def test_forged_coherent_pairs_never_authorize_transforms() -> None:
    """Self-consistent but malformed halves refuse combine and split."""
    value = _wide_value(bytes.fromhex("01 d8 11 ca c3"))
    low = replace(
        value.pair.low,
        slice=replace(
            value.pair.low.slice, result=replace(value.pair.low.result, size=1)
        ),
    )
    high = replace(
        value.pair.high,
        slice=replace(
            value.pair.high.slice, result=replace(value.pair.high.result, size=3)
        ),
    )
    unequal = replace(
        value.pair,
        low=low,
        high=high,
        type=replace(value.pair.type, low_size=1, high_size=3),
    )
    foreign = replace(
        value.pair,
        low=replace(
            value.pair.low,
            slice=replace(
                value.pair.low.slice,
                result=replace(value.pair.low.result, space=MemSpace.SS),
            ),
        ),
    )

    for forged in (unequal, foreign):
        assert forged.state is WidePairState8616.PAIRED
        assert not forged.combine_authorized
        assert not forged.split_authorized
