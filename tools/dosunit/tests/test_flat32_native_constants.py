"""Native-entry constants must survive every actual predecessor and backedge."""
import time
from typing import Any

import pytest

from tools.dosunit.compare.flat32_call_contracts import (
    CallCompositionLimits,
    _ComposeSession,
    _LiftedBlock,
    _register_widths,
)
from tools.dosunit.compare.flat32_loop_calls import compare_flat32_loop_calls
from tools.dosunit.compare.flat32_native_constants import (
    NativeConstantProof,
    native_constant_checker,
    prove_native_constants,
)
from tools.dosunit.tests.test_flat32_comparator_lane import DriverLane, _project

pytest_plugins = ["test_flat32_comparator_lane"]
BASE = 0x100000
ORIGINAL = "55 8bec 8b4508 8bd0 0bc0 7508 8b450c c9 c20800 90 83780800 7409 8b5208 837a0800 75f7 8b4d0c 894a08 c9 c20800"
CANDIDATE = "55 8bec 8b4d08 8bd1 0bc9 7507 8b450c 5d c20800 83790800 740f 2bc0 0500000000 8b5208 394208 75f8 8b450c 894208 8bc1 5d c20800"


def _literal(value: int) -> dict[str, Any]:
    """Create a native control or arithmetic literal."""
    return {"op": "const", "width": 32, "value": hex(value)}


def _input(name: str) -> dict[str, Any]:
    """Create a full-width arbitrary machine input."""
    return {"op": "input", "width": 32, "name": name}


def _blocks() -> dict[int, _LiftedBlock]:
    """Keep zero-setup and repeated loop entry as distinct physical addresses."""
    blocks = {}
    for address in range(4):
        successors = (address + 1,) if address < 2 else ((2, 3) if address == 2 else ())
        control = _literal(address + 1) if address < 2 else {
            "op": "ite", "width": 32, "args": [_input("ecx"), _literal(2), _literal(3)]}
        outputs = {"eax": _literal(0) if address == 1 else _input("eax"), "ip": control}
        blocks[address] = _LiftedBlock(address, None, {"outputs": outputs, "assignments": []},
                                      "Ijk_Ret" if address == 3 else "Ijk_Boring", successors, None, None)
    return blocks


def _prove(blocks: dict[int, _LiftedBlock]) -> Any:
    """Use the production composition budget and independent SMT discharge."""
    deadline = time.monotonic() + 10
    session = _ComposeSession(project=None, functions={0: 4}, labels={}, limits=CallCompositionLimits(),
                              reg_widths=_register_widths(), compose_stats={"deadline": deadline})
    return prove_native_constants(blocks, 0, session, deadline=deadline)


@pytest.mark.parametrize("zeroing", ["literal", "sub", "xor"])
def test_zero_is_proved_only_after_setup(zeroing: str) -> None:
    """All real incoming edges establish the repeated-entry constant."""
    blocks = _blocks()
    if zeroing != "literal":
        blocks[1].part["outputs"]["eax"] = {
            "op": zeroing, "width": 32, "args": [_input("eax"), _input("eax")]}
    result = _prove(blocks)
    assert result is not None
    assert 0 not in result.constants
    assert 1 not in result.constants
    assert result.constants[2] == {"eax": 0}
    edges = {(p["from"], p["to"]) for p in result.evidence["incoming_edge_proofs"]}
    assert {("0x1", "0x2"), ("0x2", "0x2")}.issubset(edges)


@pytest.mark.parametrize("mutation", ["bypass", "backedge", "edge_metadata", "unreachable"])
def test_incomplete_or_inconsistent_constants_rejected(mutation: str) -> None:
    """One conflicting predecessor or unknown edge invalidates the proposal."""
    from dataclasses import replace

    blocks = _blocks()
    if mutation == "bypass":
        blocks[0] = replace(blocks[0], successors=(1, 2))
        blocks[0].part["outputs"]["ip"] = {
            "op": "ite", "width": 32, "args": [_input("edx"), _literal(1), _literal(2)]}
    elif mutation == "backedge":
        blocks[2].part["outputs"]["eax"] = {
            "op": "add", "width": 32, "args": [_input("eax"), _literal(1)]}
    elif mutation == "edge_metadata":
        blocks[0] = replace(blocks[0], successors=(2,))
    else:
        blocks[4] = replace(blocks[3], address=4)
    assert _prove(blocks) is None


def test_false_synthesis_is_not_a_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even a bogus constant proposal cannot bypass universal edge checks."""
    from tools.dosunit.compare import flat32_native_constants as native

    monkeypatch.setattr(native, "_constant", lambda term: 0)
    assert _prove(_blocks()) is None


@pytest.mark.parametrize("mutation", ["none", "increment", "store"])
@pytest.mark.parametrize("normalization", [None, {0x600000: 0x700000}], ids=["literal", "relocation"])
def test_list_loop_allocation_and_zero_setup(
    lane: DriverLane, mutation: str, normalization: dict[int, int] | None,
) -> None:
    """Head-register allocation, frame teardown and loop-local zero compose."""
    candidate = CANDIDATE
    if mutation == "increment":
        candidate = candidate.replace("0500000000", "0501000000")
    elif mutation == "store":
        candidate = candidate.replace("894208", "89420c")
    result = compare_flat32_loop_calls(
        (_project(ORIGINAL, BASE), _project(candidate, BASE)),
        (BASE, len(bytes.fromhex(ORIGINAL))), (BASE, len(bytes.fromhex(candidate))),
        lane.adapter.OUTPUT_REGS, 20000, candidate_normalization=normalization,
    )
    expected = ("conditional" if normalization else "passed") if mutation == "none" else "refused"
    assert result["status"] == expected, result
    if mutation == "none":
        assert result["native_constant_invariants"]["candidate"]["incoming_edge_proofs"]
        assert result["register_relation"]
        assert result["frame_invariants"]



def test_asymmetric_constant_keeps_unrestricted_proof(lane: DriverLane, monkeypatch: pytest.MonkeyPatch) -> None:
    """A first-entry constant must not replace an already-valid shared-state proof."""
    from tools.dosunit.compare import flat32_loop_calls as calls

    def unexpected_analysis(*args: Any, **kwargs: Any) -> None:
        """An already-proved graph must not spend additional invariant budget."""
        raise AssertionError("native constant analysis ran before an existing proof")

    monkeypatch.setattr(calls, "prove_native_constants", unexpected_analysis)
    original = "55 8bec 2bc0 8b4d08 d1f9 3bc8 7407 40 d1f9 0bc9 75f9 c9 c20400"
    candidate = "55 8bec 2bc0 8b4d08 d1f9 3bc8 7409 8bff 40 d1f9 0bc9 75f9 5d c20400"
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(candidate, BASE)),
        (BASE, len(bytes.fromhex(original))), (BASE, len(bytes.fromhex(candidate))),
        lane.adapter.OUTPUT_REGS, 20000,
    )
    assert result["status"] == "passed", result
    assert not result["native_constant_invariants"]


MEM_INPUT: dict[str, Any] = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
RELOCATED_GLOBAL = 0x36864
ORACLE_GLOBAL = 0x25864


def _reloc_blocks() -> dict[int, _LiftedBlock]:
    """edx=1 survives a block that also loads through a relocated global."""
    blocks = {}
    for address in range(4):
        successors = (address + 1,) if address < 2 else ((2, 3) if address == 2 else ())
        control = _literal(address + 1) if address < 2 else {
            "op": "ite", "width": 32, "args": [_input("ecx"), _literal(2), _literal(3)]}
        outputs = {"ip": control}
        if address == 1:
            outputs["edx"] = _literal(1)
            outputs["ecx"] = _literal(RELOCATED_GLOBAL)
            outputs["eax"] = {"op": "loadle", "width": 32,
                              "args": [MEM_INPUT, _literal(RELOCATED_GLOBAL)]}
        else:
            outputs.update({name: _input(name) for name in ("eax", "ecx", "edx")})
        blocks[address] = _LiftedBlock(address, None, {"outputs": outputs, "assignments": []},
                                      "Ijk_Ret" if address == 3 else "Ijk_Boring", successors, None, None)
    return blocks


def _prove_mapped(blocks: dict[int, _LiftedBlock], normalization: dict[int, int] | None) -> Any:
    """Prove invariants inside the certified relocation domain when declared."""
    deadline = time.monotonic() + 10
    session = _ComposeSession(project=None, functions={0: 4}, labels={}, limits=CallCompositionLimits(),
                              reg_widths=_register_widths(), compose_stats={"deadline": deadline})
    return prove_native_constants(blocks, 0, session, deadline=deadline,
                                  candidate_normalization=normalization)


def test_scalar_survives_relocated_global_load() -> None:
    """EDX=1 stays admitted; the relocated literal scalar is rejected."""
    result = _prove_mapped(_reloc_blocks(), {RELOCATED_GLOBAL: ORACLE_GLOBAL})
    assert result is not None
    assert result.constants[2] == {"edx": 1}
    assert result.constants[3] == {"edx": 1}
    evidence = result.evidence
    assert evidence["scalar_domain"] == "candidate_normalization"
    assert evidence["candidate_normalization"] == {"0x36864": "0x25864"}
    assert evidence["rejected_relocated_values"] == {
        "0x2": {"ecx": "0x36864"}, "0x3": {"ecx": "0x36864"}}
    edges = {(p["from"], p["to"]) for p in evidence["incoming_edge_proofs"]}
    assert {("0x1", "0x2"), ("0x2", "0x2"), ("0x2", "0x3")}.issubset(edges)


def test_false_incoming_edge_rejected_under_normalization(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """A bogus transported fact cannot pass the normalized edge recheck."""
    from tools.dosunit.compare import flat32_native_constants as native

    forged = {0: {}, 1: {}, 2: {"edx": 7}, 3: {"edx": 7}}
    monkeypatch.setattr(native, "_infer", lambda *args: forged)
    assert _prove_mapped(_reloc_blocks(), {RELOCATED_GLOBAL: ORACLE_GLOBAL}) is None


def test_map_collision_rejects_literal_fact() -> None:
    """A relocation key colliding with a real scalar drops every fact."""
    normalization = {RELOCATED_GLOBAL: ORACLE_GLOBAL, 1: 0x25864}
    assert _prove_mapped(_reloc_blocks(), normalization) is None


def test_literal_domain_records_no_normalization() -> None:
    """Without a declared map the literal path and evidence stay untouched."""
    result = _prove_mapped(_reloc_blocks(), None)
    assert result is not None
    assert result.constants[2] == {"edx": 1, "ecx": RELOCATED_GLOBAL}
    assert "candidate_normalization" not in result.evidence
    assert "scalar_domain" not in result.evidence
    assert result.evidence["failure_count"] == 0


def _checker_stub(calls: list[Any], refined_status: str = "passed") -> Any:
    """Record checker call order for the facts-first control."""
    def check(_graph: Any, facts: Any) -> dict[str, Any]:
        calls.append(("check", facts))
        return {"status": refined_status if any(facts) else "refused",
                "block_verdicts": []}
    def infer() -> Any:
        calls.append(("infer",))
        return (NativeConstantProof({2: {"edx": 1}}, {}), None)
    return check, infer


def test_prefer_facts_first_discharges_before_plain() -> None:
    """A validated fact discharges the graph without the unrestricted pass."""
    calls: list[Any] = []
    check, infer = _checker_stub(calls)
    checker = native_constant_checker(check, infer, enabled=True, prefer_facts_first=True)
    result = checker(object())
    assert result["status"] == "passed"
    assert result["prefer_facts_first"] is True
    assert calls == [("infer",), ("check", calls[1][1])]
    assert all(call[1] != (None, None) for call in calls if call[0] == "check")


def test_prefer_facts_first_retains_failed_attempt() -> None:
    """A failed refined attempt stays visible beside the plain result."""
    calls: list[Any] = []
    check, infer = _checker_stub(calls, refined_status="refused")
    checker = native_constant_checker(check, infer, enabled=True, prefer_facts_first=True)
    result = checker(object())
    assert result["status"] == "refused"
    assert "unrestricted_native_attempt" in result
    assert calls[0] == ("infer",)


def test_default_checker_order_unchanged() -> None:
    """Without the flag the unrestricted comparison still runs first."""
    calls: list[Any] = []
    check, infer = _checker_stub(calls, refined_status="passed")
    checker = native_constant_checker(check, infer, enabled=True)
    result = checker(object())
    assert result["status"] == "passed"
    assert calls[0] == ("check", (None, None))


def test_failed_facts_preserve_successful_plain_comparison() -> None:
    """An unsuccessful fast route must not replace a complete plain proof."""
    def check(graph: Any, facts: Any) -> dict[str, Any]:
        return {"status": "refused" if any(facts) else "passed", "block_verdicts": []}

    checker = native_constant_checker(
        check, lambda: (None, NativeConstantProof({2: {"edx": 1}}, {})),
        enabled=True, prefer_facts_first=True)
    result = checker(object())
    assert result["status"] == "passed"
    assert result["native_constant_attempt"]["status"] == "refused"


@pytest.mark.parametrize("requested", [None, {0x3000: 0x1000}, {0x3000: 0x2000}])
def test_normalized_native_facts_require_exact_comparison_map(requested: Any) -> None:
    """Only the relocation domain used for every incoming proof is admissible."""
    from tools.dosunit.compare.flat32_call_contracts import CallCompositionRefusal
    from tools.dosunit.compare.flat32_loop_calls import _native_comparison_normalization

    facts = NativeConstantProof({2: {"edx": 1}}, {
        "scalar_domain": "candidate_normalization", "candidate_normalization": {"0x3000": "0x1000"}})
    if requested == {0x3000: 0x1000}:
        assert _native_comparison_normalization(facts, requested) == requested
    else:
        with pytest.raises(CallCompositionRefusal, match="native_constant_domain_mismatch"):
            _native_comparison_normalization(facts, requested)


def test_literal_candidate_facts_keep_literal_comparison() -> None:
    """Legacy invariants do not silently acquire a relocation premise."""
    from tools.dosunit.compare.flat32_loop_calls import _native_comparison_normalization

    assert _native_comparison_normalization(
        NativeConstantProof({2: {"edx": 1}}, {}), {0x3000: 0x1000}) is None
