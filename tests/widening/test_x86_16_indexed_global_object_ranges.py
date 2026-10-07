from __future__ import annotations

from dataclasses import replace

import pytest
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.indexed_address_contracts import (
    IndexedAddressAccessKind8616,
)
from inertia.ir.indexed_address_copy_contracts import (
    IndexedAddressCopyFact8616,
    IndexedAddressCopyLane8616,
    IndexedAddressCopyValuePath8616,
)
from inertia.ir.indexed_address_range_contracts import (
    IndexedLoopRangeFailureKind8616,
)
from inertia.ir.indexed_address_range_evidence import (
    collect_indexed_loop_range_evidence_8616,
)
from tests.widening.x86_16_indexed_global_object_range_fixtures import (
    FUNCTION_ADDR,
)
from tests.widening.x86_16_indexed_global_object_range_fixtures import (
    indexed_accesses_8616 as _accesses,
)
from tests.widening.x86_16_indexed_global_object_range_fixtures import (
    indexed_fact_8616 as _fact,
)
from tests.widening.x86_16_indexed_global_object_range_fixtures import (
    indexed_range_candidate_8616 as _candidate,
)
from tests.widening.x86_16_indexed_global_object_range_fixtures import (
    widen_indexed_ranges_8616 as _widen,
)

from inertia.alias.indexed_address_copy_contracts import (
    IndexedAliasCopyFact8616,
)
from inertia.alias.indexed_address_range_contracts import (
    IndexedLoopRangeAliasFailureKind8616,
)
from inertia.alias.indexed_address_range_projection import (
    project_indexed_loop_ranges_to_alias_8616,
)
from inertia.widening.global_object_layout import (
    GlobalObjectLayout8616,
    GlobalObjectLayoutEvidence8616,
)
from inertia.widening.indexed_global_object_ranges import (
    BoundedGlobalObjectRangeFailureKind8616,
)


def test_zero_based_word_range_materializes_exact_extent() -> None:
    fact = _fact(0x200, 10)
    result = _widen((fact,), (_candidate(fact),))
    assert result.closed
    assert result.refusals == ()
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1
    object_range = result.ranges[0]
    assert object_range.space is MemSpace.DS
    assert (object_range.lower_inclusive, object_range.upper_exclusive) == (0, 4)
    assert object_range.element_count == 4
    assert object_range.element_width == 2
    assert object_range.byte_extent == 8
    assert len(object_range.covered_access_keys) == 1
    assert len(object_range.proof_sites) == 4


def test_two_byte_record_fields_share_one_layout_backed_range() -> None:
    low = _fact(0x200, 10, width=1)
    high = _fact(0x201, 20, width=1)
    layout = GlobalObjectLayout8616(
        IRAddress(
            MemSpace.DS,
            offset=0x200,
            size=2,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
        2,
        (0, 1),
        0x200,
    )
    layouts = GlobalObjectLayoutEvidence8616((layout,), 1, 1, 1, 1)
    result = _widen(
        (low, high),
        (_candidate(low), _candidate(high)),
        layouts=layouts,
    )
    assert result.closed
    assert result.refusals == ()
    assert result.ranges[0].base == 0x200
    assert result.ranges[0].element_width == 2
    assert result.ranges[0].element_count == 4
    assert result.ranges[0].byte_extent == 8
    assert len(result.ranges[0].covered_access_keys) == 2


@pytest.mark.parametrize(
    ("case", "failure"),
    (
        ("dynamic", IndexedLoopRangeFailureKind8616.DYNAMIC_BOUND),
        ("init", IndexedLoopRangeFailureKind8616.INIT_UNPROVEN),
        ("bool_init", IndexedLoopRangeFailureKind8616.INIT_UNPROVEN),
        ("step", IndexedLoopRangeFailureKind8616.STEP_UNPROVEN),
        ("bool_step", IndexedLoopRangeFailureKind8616.STEP_UNPROVEN),
        ("guard", IndexedLoopRangeFailureKind8616.GUARD_UNPROVEN),
        ("dominance", IndexedLoopRangeFailureKind8616.DOMINANCE_UNPROVEN),
        ("backedge", IndexedLoopRangeFailureKind8616.BACKEDGE_UNPROVEN),
    ),
)
def test_ir_refuses_each_missing_loop_proof(
    case: str,
    failure: IndexedLoopRangeFailureKind8616,
) -> None:
    fact = _fact(0x200, 10)
    candidate = _candidate(fact)
    if case == "dynamic":
        candidate = replace(candidate, upper_bound=None, upper_bound_is_constant=False)
    elif case == "init":
        candidate = replace(candidate, init=None)
    elif case == "bool_init":
        candidate = replace(candidate, init=False)
    elif case == "step":
        candidate = replace(candidate, step=None)
    elif case == "bool_step":
        candidate = replace(candidate, step=True)
    elif case == "guard":
        candidate = replace(candidate, guard=None)
    elif case == "dominance":
        assert candidate.guard is not None
        candidate = replace(
            candidate,
            guard=replace(candidate.guard, guard_dominates_access=False),
        )
    else:
        assert candidate.natural_loop is not None
        candidate = replace(
            candidate,
            natural_loop=replace(candidate.natural_loop, backedge_proven=False),
        )
    result = collect_indexed_loop_range_evidence_8616(FUNCTION_ADDR, (candidate,))
    assert result.closed
    assert result.facts == ()
    assert result.stats.raw_fact_count == result.stats.failure_count == 1
    assert result.refusals[0].failure is failure
    if case == "dynamic":
        widened = _widen((fact,), (candidate,))
        assert widened.ranges == ()
        assert widened.stats.materialized_count == 0
        assert widened.refusals[0].failure is (
            BoundedGlobalObjectRangeFailureKind8616.UNCOVERED_ACCESS
        )


def test_alias_refuses_canonical_stack_identity_mismatch() -> None:
    fact = _fact(0x200, 10)
    accesses = _accesses(fact)
    access = accesses.facts[0]
    alias_fact = access.source
    source_range = alias_fact.storage.index_source_range
    bad_range = replace(
        source_range,
        storage=replace(source_range.storage, identity=("stack", "different")),
    )
    bad_alias_fact = replace(
        alias_fact,
        storage=replace(alias_fact.storage, index_source_range=bad_range),
    )
    bad_aliases = replace(accesses.source, facts=(bad_alias_fact,))
    bad_accesses = replace(
        accesses,
        facts=(replace(access, source=bad_alias_fact),),
        source=bad_aliases,
    )
    assert bad_accesses.closed
    source = collect_indexed_loop_range_evidence_8616(FUNCTION_ADDR, (_candidate(fact),))
    result = project_indexed_loop_ranges_to_alias_8616(source, bad_accesses)
    assert result.closed
    assert result.facts == ()
    assert result.refusals[0].failure is IndexedLoopRangeAliasFailureKind8616.IDENTITY_MISMATCH


@pytest.mark.parametrize(
    ("case", "failure"),
    (
        ("segment", BoundedGlobalObjectRangeFailureKind8616.SEGMENT_MISMATCH),
        ("wrap", BoundedGlobalObjectRangeFailureKind8616.SEGMENT_WRAP),
        ("uncovered", BoundedGlobalObjectRangeFailureKind8616.UNCOVERED_ACCESS),
        ("bounds", BoundedGlobalObjectRangeFailureKind8616.CONFLICTING_BOUNDS),
        ("stride", BoundedGlobalObjectRangeFailureKind8616.STRIDE_WIDTH_MISMATCH),
        ("overlap", BoundedGlobalObjectRangeFailureKind8616.OVERLAP),
    ),
)
def test_widening_atomically_refuses_object_conflicts(
    case: str,
    failure: BoundedGlobalObjectRangeFailureKind8616,
) -> None:
    first = _fact(0x200, 10)
    second = _fact(0x200, 20)
    facts = (first, second)
    candidates = (_candidate(first), _candidate(second))
    if case == "segment":
        second = _fact(0x200, 20, space=MemSpace.ES)
        facts = (first, second)
        candidates = (_candidate(first), _candidate(second))
    elif case == "wrap":
        first = _fact(0xFFFA, 10)
        facts = (first,)
        candidates = (_candidate(first),)
    elif case == "uncovered":
        candidates = (_candidate(first),)
    elif case == "bounds":
        candidates = (_candidate(first, 4), _candidate(second, 5))
    elif case == "stride":
        first = _fact(0x200, 10, shift=2)
        facts = (first,)
        candidates = (_candidate(first),)
    else:
        second = _fact(0x206, 20)
        facts = (first, second)
        candidates = (_candidate(first), _candidate(second))
    result = _widen(facts, candidates)
    assert result.closed
    if case == "segment":
        assert len(result.ranges) == 1
        assert result.ranges[0].space is MemSpace.DS
    else:
        assert result.ranges == ()
    assert result.refusals
    assert {item.failure for item in result.refusals} == {failure}


def test_widening_refuses_incompatible_copy_endpoint_bounds() -> None:
    load = _fact(0x200, 10)
    store = _fact(0x300, 20, kind=IndexedAddressAccessKind8616.STORE)
    accesses = _accesses(load, store)
    source_access = next(item for item in accesses.facts if item.source.source == load)
    destination_access = next(item for item in accesses.facts if item.source.source == store)
    value = IRValue(MemSpace.REG, name="ax", size=2, version=7)
    source_copy = IndexedAddressCopyFact8616(
        load,
        store,
        (store.instr_index,),
        (
            IndexedAddressCopyValuePath8616(
                store.instr_index,
                load.block_addr,
                load.instr_index,
                load.instr_addr,
                IndexedAddressCopyLane8616.DIRECT,
                value,
                value,
                (),
            ),
        ),
    )
    copy = IndexedAliasCopyFact8616(
        source_copy,
        source_access.source,
        destination_access.source,
        source_access,
        destination_access,
    )
    assert copy.complete
    result = _widen(
        (load, store),
        (_candidate(load, 4), _candidate(store, 5)),
        (copy,),
    )
    assert result.closed
    assert result.ranges == ()
    assert {item.failure for item in result.refusals} == {
        BoundedGlobalObjectRangeFailureKind8616.INCOMPATIBLE_COPY_ENDPOINTS
    }
