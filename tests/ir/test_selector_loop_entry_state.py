"""Selector induction must distinguish unvisited loop edges from unknown registers."""

import pytest

from inertia.ir import declared_selector_invariant as selector
from tests.ir.test_forward_declared_call_scope import _forward_world
from tests.ir.test_scoped_selector_callee import _prove

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("caller", [
    bytes.fromhex("31c04083f8047cfac3"),
    bytes.fromhex("31c0eb014083f8047cfac3"),
])
def test_native_loop_keeps_entry_code_selector(caller: bytes) -> None:
    """Native loops preserve CS with either body/header layout in the binary."""
    result = _prove(_forward_world(caller_bytes=caller, helper_bytes=b"\xc3"))
    assert result.status is selector.InvariantStatus.PROVEN_CONDITIONAL, result.obligations
    assert not result.obligations


@pytest.mark.parametrize("backedge", [{}, {"cs": 0x200}])
def test_visited_unknown_or_conflicting_backedge_drops_selector(backedge: dict[str, int]) -> None:
    """Known CS on the entry edge cannot override an already visited conflicting edge."""
    assert "cs" not in selector._join_entry(
        0x1000, 0x1010, {"cs": 0x100}, [0x1000, 0x1020],
        {0x1000: {"cs": 0x100}, 0x1020: backedge})
