"""Actual i386 nested/early-exit/partial-register induction controls.

Both real adapter lanes lift byte bodies at distinct load bases.
Candidate NOPs preserve instruction effects without making bytes identical.
"""
from typing import Protocol

import pytest
from test_flat32_comparator_lane import DriverLane, _compare_loops

pytest_plugins = ["test_flat32_comparator_lane"]


class LoopFactory(Protocol):
    """Build equivalent or corrupt instruction bodies."""

    def __call__(self, *, candidate: bool = False, corrupt: bool = False) -> str:
        """Return one complete machine-code body."""
        ...


def body(parts: list[str | tuple[int, str]]) -> str:
    """Encode explicit x86 short branches against local instruction labels."""
    result = bytearray()
    labels = {}
    branches = []
    for item in parts:
        if isinstance(item, str) and item.endswith(":"):
            labels[item[:-1]] = len(result)
        elif isinstance(item, tuple):
            opcode, label = item
            result.append(opcode)
            branches.append((len(result), label))
            result.append(0)
        else:
            result.extend(bytes.fromhex(item))
    for index, label in branches:
        delta = labels[label] - index - 1
        assert -128 <= delta < 128
        result[index] = delta & 255
    return result.hex()


def nested(*, candidate: bool = False, corrupt: bool = False) -> str:
    """ECX outer trips and EBX inner trips; EDX is the inner live counter."""
    return body([
        "85c9", (0x74, "done"), "outer:", "89da", "inner:", "85d2",
        (0x74, "inner_done"), "90" if candidate else "",
        "83c002" if corrupt else "83c001", "4a", (0xeb, "inner"),
        "inner_done:", "49", (0x75, "outer"), "done:", "c3",
    ])


def early_exit(*, candidate: bool = False, corrupt: bool = False) -> str:
    """The sign guard inside the loop can return before the remaining trips."""
    return body([
        "85c9", (0x74, "done"), "loop:", "85d2" if corrupt else "85c0",
        (0x78, "done"), "90" if candidate else "",
        "01d0", "49", (0x75, "loop"), "done:", "c3",
    ])


def partial(width: int, *, candidate: bool = False, corrupt: bool = False) -> str:
    """AL/AX loop updates must preserve the untouched upper register bits."""
    update = {8: "00d0", 16: "6601d0"}[width]
    if corrupt:
        update = {8: "00d4", 16: "01d0"}[width]
    return body([
        "85c9", (0x74, "done"), "loop:", "90" if candidate else "",
        update, "49", (0x75, "loop"), "done:", "c3",
    ])


@pytest.mark.parametrize("factory", [nested, early_exit], ids=["nested", "early_exit"])
def test_changed_code_loop_shape_proves(lane: DriverLane, factory: LoopFactory) -> None:
    """Nested and mid-body-return loops prove across harmless byte changes."""
    oracle, candidate = factory(), factory(candidate=True)
    assert oracle != candidate
    result = _compare_loops(lane, oracle, candidate)
    assert result["status"] is lane.verdict.Status.PASSED, result
    assert result["reason"] == "reblocked_cfg_induction", result


@pytest.mark.parametrize("factory", [nested, early_exit], ids=["nested_stride", "early_guard"])
def test_loop_shape_mutation_rejected(lane: DriverLane, factory: LoopFactory) -> None:
    """Changed stride or exit predicate must fail a compared transition."""
    result = _compare_loops(lane, factory(), factory(candidate=True, corrupt=True))
    assert result["status"] is lane.verdict.Status.REFUSED, result
    assert any(row["status"] is lane.verdict.Status.FAILED for row in result["block_verdicts"]), result


@pytest.mark.parametrize("width", [8, 16], ids=["byte", "word"])
def test_partial_register_cutpoint_proves(lane: DriverLane, width: int) -> None:
    """Matching partial updates preserve the whole observable register."""
    result = _compare_loops(lane, partial(width), partial(width, candidate=True))
    assert result["status"] is lane.verdict.Status.PASSED, result
    assert result["reason"] == "reblocked_cfg_induction", result


@pytest.mark.parametrize("width", [8, 16], ids=["byte_target", "word_upper_half"])
def test_partial_register_cutpoint_mutation_rejected(lane: DriverLane, width: int) -> None:
    """Wrong byte target or widened word update fails transition equality."""
    result = _compare_loops(lane, partial(width), partial(width, candidate=True, corrupt=True))
    assert result["status"] is lane.verdict.Status.REFUSED, result
    assert any(row["status"] is lane.verdict.Status.FAILED for row in result["block_verdicts"]), result
