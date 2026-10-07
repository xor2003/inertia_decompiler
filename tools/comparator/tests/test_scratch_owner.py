"""Scratch retry preserves conditional accounting and input document ownership."""

import copy

import pytest

from tools.comparator.msc8_scratch import retry_scratch_frame
from tools.comparator.verdict import Status


@pytest.mark.parametrize("status", [Status.PASSED, Status.FAILED, Status.REFUSED])
def test_scratch_retry_never_promotes_backend_nonproof(status):
    document = {"functions": [{"function": {"name": "f"}, "assignments": [],
                               "inputs": [], "outputs": {"eax": {"op": "input", "name": "eax", "width": 32}}}]}
    original = copy.deepcopy(document)

    def compare(**kwargs):
        assert kwargs["skip_binary_equal"] is False
        assert kwargs["oracle"] is not document
        return {"results": [{"function": {"name": "f"}, "status": status}]}

    result = retry_scratch_frame([{"function": {"name": "f"}}], document, document, compare, 100)
    assert document == original
    if status is Status.PASSED:
        assert result["f"]["status"] is Status.CONDITIONAL
        assert result["f"]["assumptions"]["kind"] == "scratch_frame_stores_masked"
    else:
        assert result == {}
