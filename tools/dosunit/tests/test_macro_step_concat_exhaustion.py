"""Exhausted frontier search must not spend unbounded empty iterations."""

import time
from collections.abc import Iterator

import pytest

import tools.dosunit.compare.macro_step_pairing as pairing
from tools.dosunit.compare.macro_step_contracts import FrontierPath, MacroEndpointKind, MacroStepLimits
from tools.dosunit.compare.paired_region_graph import CollapsedRegion, RegionExitKind


def test_terminal_only_frontier_stops_after_first_empty_extension(monkeypatch: pytest.MonkeyPatch) -> None:
    """No further paths can appear once every frontier ends at a return."""
    path = FrontierPath((CollapsedRegion((0,), (), RegionExitKind.RETURN),), 0, 0, MacroEndpointKind.RETURN)
    budget = pairing._SearchBudget(MacroStepLimits(), time.monotonic() + 5)

    def bounded_range(*args: int) -> Iterator[int]:
        """Allow one extension round and reject redundant empty rounds."""
        yield 2
        raise AssertionError("enumeration continued after frontier exhaustion")

    monkeypatch.setattr(pairing, "range", bounded_range, raising=False)
    assert pairing._enumerate_concats((path,), 1_000_000, budget) == ((path,),)
