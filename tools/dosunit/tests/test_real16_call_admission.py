"""Binary range and identity admission for direct real16 call proofs."""

from copy import deepcopy
from pathlib import Path

import pytest
from tools.dosunit.tests.test_real16_call_composition import _caller_bytes, _caller_catalog, _lower

from tools.dosunit.compare.real16_call_composition import compare_real16_with_calls


@pytest.mark.parametrize("field", ["function_machine_code_size", "function_machine_code_sha256"])
def test_missing_whole_body_identity_refuses(tmp_path: Path, field: str) -> None:
    """Entry/block fingerprints cannot replace the declared whole body."""
    original = _lower(tmp_path, _caller_bytes(), _caller_catalog(), "original")
    incomplete = deepcopy(original)
    for part in incomplete["functions"]:
        del part["source"][field]
    result = compare_real16_with_calls(original, incomplete, "demo.exe:caller")
    assert result["status"] == "refused", result
    assert result["reason"] == "function_range_incomplete", result
