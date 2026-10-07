"""Incomplete guard membership or missing progress evidence cannot compose."""
import pytest

from tools.dosunit.compare.flat32_cfg_regions import _check_composition_inputs
from tools.dosunit.compare.paired_region_graph import (
    CollapsedRegion,
    RegionExitKind,
    RegionGraphReason,
    RegionGraphRefusal,
)


@pytest.mark.parametrize('members,docs,tokens,reason', [
    ((), [], (), RegionGraphReason.MEMBERS),
    ((0, 1), [{'outputs': {}}], (), RegionGraphReason.MEMBERS),
    ((0, 1), [{'outputs': {}}, {'outputs': {}}], (), RegionGraphReason.PROGRESS_MISSING),
    ((0,), [{'outputs': {}}], (3,), RegionGraphReason.PROGRESS_MISSING),
])
def test_incomplete_transition_evidence_refuses(members, docs, tokens, reason):
    region = CollapsedRegion(members, (2,), RegionExitKind.BORING)
    with pytest.raises(RegionGraphRefusal) as caught:
        _check_composition_inputs(region, docs, tokens)
    assert caught.value.reason is reason
