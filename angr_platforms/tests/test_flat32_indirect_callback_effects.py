"""Parent controls for selector caching and callee memory effects."""

from collections.abc import Iterator
from typing import Any

import pytest
import test_flat32_indirect_callbacks as fixture


@pytest.fixture(params=["msc8", "bc5"])
def lane(request: pytest.FixtureRequest) -> Iterator[dict[str, Any]]:
    """Exercise each public driver's adapter with isolated module state."""
    with fixture._driver_lane(str(request.param)) as imported:
        yield imported


def test_duplicate_target_keeps_each_return_obligation(lane):
    """Shared callee composition must not erase distinct selector obligations."""
    body = fixture.F_CMOV3.replace(
        f"b9{fixture._imm32(fixture.CB_C)}",
        f"b9{fixture._imm32(fixture.CB_A)}",
    )
    functions = fixture._functions(body)
    result = fixture._compare(
        lane["flat32_adapter"], fixture._image(body), fixture._image(body),
        oracle_functions=functions, candidate_functions=functions,
    )
    assert result["status"] == "passed", result
    assert result["oracle_inlined_calls"] == 2, result
    assert result["return_targets_proved"] == 6, result


def test_indirect_callee_memory_mutation_is_observable(lane):
    """A write outside the return slot survives the merged callee summary."""
    original = "c744240801000000 c3"
    changed = "c744240802000000 c3"
    result = fixture._compare(
        lane["flat32_adapter"],
        fixture._image(fixture.F_CMOV, cb_b=original),
        fixture._image(fixture.F_CMOV, cb_b=changed),
        oracle_functions=fixture._functions(fixture.F_CMOV, cb_b=original),
        candidate_functions=fixture._functions(fixture.F_CMOV, cb_b=changed),
    )
    assert result["status"] == "failed", result


def test_duplicate_target_mutation_is_still_observable(lane):
    """Reusing the first target on another arm cannot hide its changed effect."""
    body = fixture.F_CMOV3.replace(
        f"b9{fixture._imm32(fixture.CB_C)}",
        f"b9{fixture._imm32(fixture.CB_A)}",
    )
    changed = "83c009 c3"
    result = fixture._compare(
        lane["flat32_adapter"], fixture._image(body),
        fixture._image(body, cb_a=changed),
        oracle_functions=fixture._functions(body),
        candidate_functions=fixture._functions(body, cb_a=changed),
    )
    assert result["status"] == "failed", result
