"""Small reconverging functions retain all stores under the existing solver gate."""
import pytest

from tools.dosunit.tests.test_flat32_comparator_lane import BASE, _compare_calls, _driver_lane

pytestmark = [pytest.mark.ssa_z3, pytest.mark.runtime]


def _store_diamonds(changed: bool) -> bytes:
    """Four independent choices feed eight observable stores after their joins."""
    code = bytearray.fromhex("31c9")
    for bit in range(4):
        code += bytes.fromhex("f7c2") + (1 << bit).to_bytes(4, "little")
        code += bytes.fromhex("740683c9") + bytes([1 << bit])
        code += bytes.fromhex("894e") + bytes([bit * 4])
    for offset in range(16, 48, 4):
        code += bytes.fromhex("894e") + bytes([offset])
    if changed:
        code += bytes.fromhex("c7462cffffffff")
    code += bytes.fromhex("b82a000000c3")
    return bytes(code)


@pytest.mark.parametrize("changed", [False, True])
def test_small_diamonds_do_not_multiply_memory_stores(changed: bool) -> None:
    """Keep the full memory observation; a corrupted final cell must still fail."""
    left, right = _store_diamonds(False), _store_diamonds(changed)
    with _driver_lane("msc8") as lane:
        result = _compare_calls(
            lane, left.hex(), right.hex(),
            oracle_functions={BASE: len(left)}, candidate_functions={BASE: len(right)},
            outputs=("eax",),
        )
    assert result["status"] == ("failed" if changed else "passed"), result
