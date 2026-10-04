"""Actual-MZ finite indirect calls with two live symbolic selector arms.

No SSA or proof is mocked. Unknown CX bit 4 chooses either target at runtime;
both arms must contribute full-state callee effects and dependency evidence.
"""

from pathlib import Path

import pytest
from test_dosunit_tool import _edge_function
from test_real16_call_composition import _lower

from tools.dosunit.real16_call_composition import compare_real16_with_calls
from tools.dosunit.real16_call_contracts import Real16CallLimits

# AND CX,10h; OR CH,1; PUSH CX; PUSH 0240h; MOV BP,SP; LCALL [BP]; RET.
# Selector 0100h/0110h gives linear 1240h/1340h. The loader base is 1000h.
# The 15-byte call prefix keeps fallthrough within the entry-alias window.
CALLER = bytes.fromhex("83e11080cd015168400289e5ff5e00c3")
FIRST = bytes.fromhex("bb0100cb")
SECOND = bytes.fromhex("bb0200cb")


def _document(tmp_path: Path, tag: str, second: bytes = SECOND,
              *, omit_second: bool = False) -> dict:
    """Lower complete MZ functions while retaining all state observables."""
    image = bytearray(0x400)
    bodies = [("caller", 0x200, CALLER), ("first", 0x240, FIRST),
              ("second", 0x340, second)]
    catalog = []
    for name, offset, body in bodies:
        image[offset:offset + len(body)] = body
        if name != "second" or not omit_second:
            catalog.append(_edge_function(f"demo.exe:{name}", name,
                                          offset=offset, size=len(body)))
    # Shared native helper requests every INTERNAL_STATE_REGS output.
    return _lower(tmp_path, bytes(image), catalog, tag)


@pytest.mark.parametrize("second", [SECOND, bytes.fromhex("c7c30200cb")],
                         ids=["self", "equivalent-second-arm"])
def test_two_live_far_targets_prove_with_both_dependencies(tmp_path: Path, second: bytes) -> None:
    """Two live targets at the inclusive cap prove with both dependencies."""
    oracle = _document(tmp_path, "oracle")
    candidate = _document(tmp_path, "candidate", second)
    result = compare_real16_with_calls(
        oracle, candidate, "demo.exe:caller", timeout_ms=20000,
        limits=Real16CallLimits(max_indirect_call_targets=2),
    )
    assert result["status"] == "passed", result
    assert result["calls"]["indirect_call_sites"] == 2, result
    assert result["calls"]["indirect_targets_proved"] == 4, result
    assert result["calls"]["return_targets_proved"] == 4, result
    assert result["calls"]["cs_preserved_proved"] == 4, result
    assert len(result["dependencies"]) == 2, result
    for side in result["dependencies"]:
        assert {callee["function"] for callee in side["callees"]} == {
            "demo.exe:first", "demo.exe:second",
        }, result


def test_second_live_arm_effect_mutation_is_counterexample(tmp_path: Path) -> None:
    """Changing only the second target remains observable in merged state."""
    result = compare_real16_with_calls(
        _document(tmp_path, "oracle"),
        _document(tmp_path, "candidate", bytes.fromhex("bb0300cb")),
        "demo.exe:caller", timeout_ms=20000,
    )
    assert result["status"] == "failed", result
    assert result["calls"]["indirect_targets_proved"] == 4, result
    assert any(item.get("reg") == "bx" for item in result["mismatches"]), result


def test_missing_second_live_target_refuses_coverage(tmp_path: Path) -> None:
    """One catalog target cannot cover both possible runtime destinations."""
    result = compare_real16_with_calls(
        _document(tmp_path, "oracle"),
        _document(tmp_path, "candidate", omit_second=True),
        "demo.exe:caller", timeout_ms=20000,
    )
    assert result["status"] == "refused", result
    assert result["reason"] == "call_target_unresolved", result


def test_two_live_targets_exceed_one_arm_budget(tmp_path: Path) -> None:
    """A live second target exceeds cap one rather than being truncated."""
    result = compare_real16_with_calls(
        _document(tmp_path, "oracle"), _document(tmp_path, "candidate"),
        "demo.exe:caller", timeout_ms=20000,
        limits=Real16CallLimits(max_indirect_call_targets=1),
    )
    assert result["status"] == "refused", result
    assert result["reason"] == "compose_budget_exceeded", result
    assert result["detail"] == {"counter": "indirect_call_targets", "limit": 1}, result
