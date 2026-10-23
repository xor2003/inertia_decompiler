"""Layer: IR tests.
Responsibility: preserve selector-record batch cardinality and native mutation refusal.
"""
import sys
from dataclasses import replace
from types import CodeType

import pytest

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("mutation", ["none", "late_record", "late_index", "native", "foreign_scope", "duplicates", "mixed_foreign", "mixed_full_native", "mixed_full_index"])
def test_native_record_batch(mutation: str) -> None:
    """Two native calls share authority while all late corruptions refuse."""
    from inertia.ir import declared_selector_call_preservation as collector
    from inertia.ir.entry_domain_call_preservation import consume_entry_selector_call_preservation_batch_8616
    from tests.ir.test_forward_declared_call_scope import _collect, _forward_world
    from tests.ir.test_scoped_selector_callee import _prove

    world = _forward_world(helper_bytes=b"\xc3")
    scope = _prove(world)
    records = collector.collect_declared_selector_call_preservations_8616(world[0], scope)
    assert len(records) == 2 and all(row.failure is None for row in records)
    assert all(row.callee is None for row in records)
    if mutation in ("mixed_full_native", "mixed_full_index"):
        full = _collect(world)[0]
        assert full.callee is not None
        records = (replace(records[0], callee=full.callee), records[1])
        assert records[0].complete_for_selector(scope)
    offered_scope = replace(scope) if mutation == "foreign_scope" else scope
    offered = (records[0], records[0]) if mutation == "duplicates" else records
    if mutation == "mixed_foreign":
        offered = (records[0], replace(records[1], artifact=replace(records[1].artifact)))
    fired = []
    def mutate(code: CodeType, offset: int, value: object) -> None:
        if fired:
            return
        fired.append(True)
        if mutation == "late_record":
            object.__setattr__(records[0], "materialized_count", 0)
        elif mutation in ("late_index", "mixed_full_index"):
            records[0].index._entries_by_normalized_target.clear()
        elif mutation in ("native", "mixed_full_native"):
            world[0].loader.memory.store(0x1050, b"\x90")
    sys.monitoring.use_tool_id(4, "selector-record-batch-mutation")
    sys.monitoring.register_callback(4, sys.monitoring.events.PY_RETURN, mutate)
    sys.monitoring.set_local_events(4, collector._bound_record_8616.__code__, sys.monitoring.events.PY_RETURN)
    try:
        verdicts = consume_entry_selector_call_preservation_batch_8616(offered, offered_scope)
    finally:
        sys.monitoring.set_local_events(4, collector._bound_record_8616.__code__, 0)
        sys.monitoring.register_callback(4, sys.monitoring.events.PY_RETURN, None)
        sys.monitoring.free_tool_id(4)
    assert len(verdicts) == len(offered)
    expected = (True, True) if mutation == "none" else (True, False) if mutation == "mixed_foreign" else (False, False)
    assert verdicts == expected
    if mutation in ("late_record", "late_index", "native", "mixed_full_native", "mixed_full_index"):
        assert fired
