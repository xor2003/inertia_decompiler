"""Native direction domains preserve both DF values and generic SSA freedom."""
import time

import pytest

from tools.dosunit.architectures.flat32_entry_inputs import bind_direction_input
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.real16_call_contracts import materialize_function
from tools.dosunit.contracts.ssa import LowerFailure
from tools.dosunit.tests.test_flat32_comparator_lane import BASE, _compare_calls, _driver_lane

pytestmark = pytest.mark.ssa_z3


def _document(width=32, name="d"):
    return {"inputs": [{"name": name, "width": width}], "assignments": [],
            "outputs": {"eax": {"op": "input", "name": name, "width": width}}}


def test_generic_direction_name_does_not_imply_architecture():
    doc = _document()
    square = materialize_function("square", {"eax": {"op": "mul", "width": 32,
                                                    "args": [doc["outputs"]["eax"]] * 2}})
    one = {**doc, "outputs": {"eax": {"op": "const", "width": 32, "value": "0x1"}}}
    assert S._compare_functions(square, one, timeout_ms=1000)["status"] == "failed"
    bound = bind_direction_input(square, architecture_name="X86", compose_stats={})
    assert S._compare_functions(bound, one, timeout_ms=1000)["status"] == "passed"
    assert square["assignments"][0]["args"][0]["name"] == "d"
    assert bound["inputs"] == [{"name": "x86_df", "width": 1}]


@pytest.mark.parametrize("opcode,flag", [("fc", 1), ("fd", 0)])
def test_native_direction_retains_both_counterexamples(opcode, flag):
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, opcode + "c3", "c3",
            oracle_functions={BASE: 2}, candidate_functions={BASE: 1}, outputs=("d",))
    assert result["status"] == "failed", result
    mismatch = next(m for m in result["mismatches"] if m.get("reg") == "d")
    assert int(mismatch["counterexample"]["x86_df"], 16) == flag
    assert "d" not in mismatch["counterexample"]
    assert result["architectural_input_bindings"]["candidate"]["d"]["width"] == 1


def test_native_callee_still_receives_caller_direction():
    # CMP EAX,EAX; CLD; CALL callee; RET / callee: PUSHFD; POP EAX; RET.
    original = "39c0fce801000000c39c58c3"
    candidate = "39c0fc9c58c3"
    with _driver_lane("msc8") as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: 9, BASE + 9: 3}, candidate_functions={BASE: 6}, outputs=("eax", "d"))
    # Strict memory includes the CALL return-slot write. Registers must still
    # retain the caller's cleared DF, rather than a fresh callee bit.
    assert result["status"] in {"passed", "failed"}, result
    assert not any(m.get("reg") in {"eax", "d"} for m in result.get("mismatches", []))


@pytest.mark.parametrize("case", ["width", "collision", "architecture", "deadline"])
def test_native_direction_rejects_invalid_binding(case):
    document = _document(16 if case == "width" else 32)
    if case == "collision":
        document["outputs"]["other"] = {"op": "input", "name": "x86_df", "width": 1}
    with pytest.raises(LowerFailure):
        bind_direction_input(document, architecture_name="AMD64" if case == "architecture" else "X86",
            compose_stats={"deadline": time.monotonic() - 1} if case == "deadline" else {})
