"""Full-state macro-step delivery must observe changes at physical returns."""

import angr
import pytest
from test_flat32_comparator_lane import _driver_lane

from tools.dosunit.flat32_macro_proof import compare_macro_cfg

ORACLE = bytes.fromhex("e3088d5b018d49ffebf6c3")
CANDIDATE_PREFIX = bytes.fromhex("e3108d5b018d49ffe3088d5b018d49ffebee")


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("tail", [bytes.fromhex("f9c3"), bytes.fromhex("b901000000c3")], ids=["carry", "ecx"])
def test_return_mutation_is_observable_with_standard_entry(driver: str, tail: bytes) -> None:
    """The full-state proof contract cannot silently fall back to ABI outputs."""
    candidate = CANDIDATE_PREFIX + tail
    oracle_base, candidate_base = 0x12345000, 0x23456000
    with _driver_lane(driver) as lane:
        projects = (
            angr.load_shellcode(ORACLE, arch="x86", load_address=oracle_base),
            angr.load_shellcode(candidate, arch="x86", load_address=candidate_base),
        )
        result = compare_macro_cfg(
            projects, (oracle_base, len(ORACLE)), (candidate_base, len(candidate)),
            lane.adapter.OUTPUT_REGS, 15000,
        )
        assert result["status"] is not lane.verdict.Status.PASSED
