"""Native scans discard old arithmetic flags only when an iteration executes."""
import pytest

from tools.dosunit.tests.test_flat32_comparator_lane import BASE, _compare_calls, _driver_lane

pytestmark = [pytest.mark.ssa_z3, pytest.mark.runtime]


@pytest.mark.parametrize("operation", ["f2ae", "f3ae", "f2af", "f3af", "66f2af", "f2a6", "f3a6", "f3a7", "f366a7"])
@pytest.mark.parametrize("count", [0, 3])
def test_scan_respects_zero_count_flag_boundary(operation: str, count: int) -> None:
    """LAHF observes old flags at zero count and scan-produced flags otherwise."""
    prefix = "b9" + count.to_bytes(4, "little").hex()
    original = prefix + "83f800" + operation + "9f0fb6c4c3"
    candidate = prefix + "83f801" + operation + "9f0fb6c4c3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))},
            outputs=("eax", "ecx", "esi", "edi"))
    assert result["status"] == ("passed" if count else "failed"), result


@pytest.mark.parametrize("operation", ["f2ae", "f3a6"])
def test_scan_direction_is_still_observable(operation: str) -> None:
    """Opposite directions cannot share a count/index summary accidentally."""
    original = "b903000000fc" + operation + "c3"
    candidate = "b903000000fd" + operation + "c3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))},
            outputs=("ecx", "esi", "edi"))
    assert result["status"] == "failed", result
