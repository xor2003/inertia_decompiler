"""Layer: tests.
Responsibility: retain dead port reads in the observable environment state.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import archinfo
import pytest
import pyvex
import z3
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from test_flat32_comparator_lane import _driver_lane

from tools.dosunit import straightline_ssa as S


@contextmanager
def _lane(name: str) -> Iterator[tuple[Any, str]]:
    if name == "real16":
        yield Arch86_16(), "ax"
    else:
        with _driver_lane(name) as driver, driver.adapter.installed(region=True):
            yield archinfo.ArchX86(), "eax"


def _lower(code: str, arch: Any, output: str) -> dict[str, Any]:
    block = pyvex.IRSB(bytes.fromhex(code), 0x401000, arch, opt_level=0)
    lowered = S._lower_irsb(block, output_regs=(output,), max_assignments_per_function=128)
    assert isinstance(lowered, dict), lowered
    return lowered


def _io_expression(function: dict[str, Any]) -> Any:
    if "io" not in function["outputs"]:
        function["outputs"]["io"] = S._materialize(
            S.SsaExpr("mem_input", 0, name="io"), assignments=[], memo={},
            object_memo={}, max_assignments_per_function=128,
        )
        function["inputs"].append({"kind": "memory", "name": "io", "addr_width": 32, "value_width": 8})
    inputs = S._z3_inputs(function, function, z3)
    pairs, skipped = S._z3_output_pairs(
        ["io"], oracle=function, candidate=function,
        oracle_outputs=function["outputs"], candidate_outputs=function["outputs"],
        inputs=inputs, z3=z3, simplify_terms=False,
    )
    assert not skipped and len(pairs) == 1
    return pairs[0][1]


@pytest.mark.parametrize("lane", ["real16", "msc8", "bc5"])
def test_unused_read_still_changes_environment_state(lane: str) -> None:
    with _lane(lane) as (arch, output):
        lowered = _lower("ec31c0c3", arch, output)
        assert "io" in lowered["outputs"]


@pytest.mark.parametrize("lane", ["real16", "msc8", "bc5"])
@pytest.mark.parametrize("changed", ["31c0c3", "ecec31c0c3", "ee31c0c3"])
def test_removed_extra_or_changed_event_is_distinguishable(lane: str, changed: str) -> None:
    with _lane(lane) as (arch, output):
        original = _io_expression(_lower("ec31c0c3", arch, output))
        candidate = _io_expression(_lower(changed, arch, output))
        solver = z3.Solver()
        solver.set(timeout=1000)
        solver.add(original != candidate)
        assert solver.check() == z3.sat


@pytest.mark.parametrize("lane", ["real16", "msc8", "bc5"])
def test_identical_read_trace_remains_equal(lane: str) -> None:
    with _lane(lane) as (arch, output):
        original = _io_expression(_lower("ecec31c0c3", arch, output))
        candidate = _io_expression(_lower("ecec31c0c3", arch, output))
        solver = z3.Solver()
        solver.set(timeout=1000)
        solver.add(original != candidate)
        assert solver.check() == z3.unsat


@pytest.mark.parametrize("lane", ["real16", "msc8", "bc5"])
@pytest.mark.parametrize("instruction", ["ec", "ed", "66ed"])
def test_native_port_width_survives_helper_abi(lane: str, instruction: str) -> None:
    """The helper byte/bit encoding must retain the decoded operand width."""
    expected = 8 if instruction == "ec" else 16 if lane == "real16" else 32
    if instruction == "66ed":
        expected = 32 if lane == "real16" else 16
    with _lane(lane) as (arch, output):
        lowered = _lower(instruction + "31c0c3", arch, output)
    reads = [item for item in lowered["assignments"] if item.get("op") == "summary_io_in"]
    assert len(reads) == 1
    assert reads[0]["width"] == expected
    assert "io" in lowered["outputs"]


@pytest.mark.parametrize("width", [0, 3, 7, 64, None])
def test_unknown_port_width_refuses_instead_of_guessing(width: int | None) -> None:
    term = (S.SsaExpr("input", 16, name="port_width") if width is None
            else S.SsaExpr("const", 16, value=width))
    assert isinstance(S._dirty_io_value_width(term, kind="input"), S.LowerFailure)


@pytest.mark.parametrize("lane", ["real16", "msc8", "bc5"])
@pytest.mark.parametrize("instruction", ["ee", "ef", "66ef"])
def test_native_output_width_survives_helper_abi(lane: str, instruction: str) -> None:
    """OUT preserves decoded operand width through both helper encodings."""
    expected = 8 if instruction == "ee" else 16 if lane == "real16" else 32
    if instruction == "66ef":
        expected = 32 if lane == "real16" else 16
    with _lane(lane) as (arch, output):
        lowered = _lower(instruction + "31c0c3", arch, output)
    writes = [item for item in lowered["assignments"] if item.get("op") == "summary_io_out"]
    assert len(writes) == 1
    # The serialized event must retain the canonical operand width in bits.
    expression = writes[0]
    assert "io" in lowered["outputs"]
    assert int(expression["args"][-1]["value"], 16) == expected
