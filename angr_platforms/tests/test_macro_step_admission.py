"""Independent rejection contracts required before macro-step promotion."""

import time
from typing import cast

import pytest

from tools.dosunit import macro_step_pairing as pairing
from tools.dosunit import region_path_terms as terms
from tools.dosunit.macro_step_contracts import MacroStepLimits, MacroStepReason, MacroStepRefusal
from tools.dosunit.paired_region_graph import RegionExitKind, RegionNode, collapse_regions


def test_return_frontiers_obey_path_limit() -> None:
    """Return paths consume the same path budget as continuing paths."""
    nodes = {
        0: RegionNode(0, (1, 2), RegionExitKind.BORING),
        1: RegionNode(1, (), RegionExitKind.RETURN),
        2: RegionNode(2, (), RegionExitKind.RETURN),
    }
    budget = pairing._SearchBudget(MacroStepLimits(max_paths_per_cut=1), time.monotonic() + 5)
    with pytest.raises(MacroStepRefusal) as refused:
        pairing._expand_frontier(collapse_regions(nodes, 0), frozenset({0}), budget)
    assert refused.value.reason is MacroStepReason.MACRO_PATH_LIMIT


@pytest.mark.parametrize("width", [None, 0, -1, True, "32"])
def test_missing_or_invalid_width_refuses(width: object) -> None:
    """A malformed scalar cannot acquire a guessed bitvector sort."""
    term: terms.Term = {"op": "input"}
    if width is not None:
        term["width"] = width
    with pytest.raises(MacroStepRefusal) as refused:
        terms.scalar_sentinel(term)
    assert refused.value.reason is MacroStepReason.MACRO_ADMISSION


def test_malformed_memory_cannot_disappear() -> None:
    """Invalid state must refuse rather than silently shrink observables."""
    with pytest.raises(MacroStepRefusal) as refused:
        # Deliberately corrupt a nominally typed boundary to test rejection.
        terms.masked_state(cast(dict[str, terms.Term], {"memory": None}), terms.guard_true())
    assert refused.value.reason is MacroStepReason.MACRO_ADMISSION
