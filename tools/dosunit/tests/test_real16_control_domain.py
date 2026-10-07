"""Full control width and nonvacuous architectural loop-domain regressions."""

from pathlib import Path

import pytest
from tools.dosunit.tests.test_dosunit_tool import _edge_function, _mz_exe
from tools.dosunit.tests.test_real16_call_composition import _lower

from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.compare.real16_call_composition import compare_real16_with_calls
from tools.dosunit.compare.real16_call_contracts import FunctionCtx, Real16CallRefusal, prove_terms_equal
from tools.dosunit.compare.real16_call_control import checked_call_site
from tools.dosunit.contracts.real16_entry_domain import code_entry_domain
from tools.dosunit.compare.real16_loop_invariants import check_cutpoint_state, check_physical_successors
from tools.dosunit.runtime.real16_mz_load import image_from_mz_bytes
from tools.dosunit.runtime.real16_replay import replay
from tools.dosunit.runtime.real16_replay_model import CallerFrame, FrameKind, Real16ReplayStatus, Real16Vector, SegOffset
from tools.dosunit.ssa.ssa_constant_terms import constant_bitvector


def _context() -> FunctionCtx:
    return FunctionCtx("demo.exe:loop", "loop", 0x1200, {0: {}, 4: {}}, 8, "0" * 64)


@pytest.mark.parametrize("entry", [-1, 0x10FFF0])
def test_unrepresentable_code_entry_has_no_domain(entry):
    assert code_entry_domain(entry) is None


@pytest.mark.parametrize("entry", [0, 0x1200, 0xFFFF, 0x100000, 0x10FFEF])
def test_code_entry_domain_exact_boundaries(entry):
    domain = code_entry_domain(entry)
    assert domain is not None
    assert 0 <= entry - 16 * domain.minimum_cs <= 0xFFFF
    assert 0 <= entry - 16 * domain.maximum_cs <= 0xFFFF
    if domain.minimum_cs > 0:
        assert entry - 16 * (domain.minimum_cs - 1) > 0xFFFF
    if domain.maximum_cs < 0xFFFF:
        assert entry - 16 * (domain.maximum_cs + 1) < 0


def test_selector_predicate_requires_and_preserves_its_input_domain():
    domain = code_entry_domain(0x1200)
    assert domain is not None
    predicate = domain.contains({"op": "input", "name": "cs", "width": 16})
    true = {"op": "const", "width": 1, "value": "0x1"}
    assert prove_terms_equal(predicate, true, 3000) is not ProofStatus.PROVED
    assert prove_terms_equal(predicate, true, 3000, input_constraints=domain.constraints()) is ProofStatus.PROVED
    retained = {"control_ip": {"op": "const", "width": 32, "value": "0x1204"},
                "cs": {"op": "input", "name": "cs", "width": 16}}
    check_cutpoint_state(_context(), retained, continuing=True, timeout_ms=3000)
    retained["cs"] = {"op": "const", "width": 16, "value": "0xffff"}
    with pytest.raises(Real16CallRefusal, match="cutpoint_code_domain_unproved"):
        check_cutpoint_state(_context(), retained, continuing=True, timeout_ms=3000)


def test_word_control_cannot_supply_loop_full_control_obligation():
    with pytest.raises(Real16CallRefusal, match="full_control_unobserved"):
        check_cutpoint_state(_context(), {"control_ip": {"op": "const", "width": 16, "value": "0x1204"}},
                             continuing=False, timeout_ms=3000)


def test_physical_loop_successor_cannot_match_only_after_word_wrapping():
    check_physical_successors(_context(), {"transfer": {"kind": "direct_successors",
                                                       "successors": [{"linear": "0x1204"}]}})
    with pytest.raises(Real16CallRefusal, match="successor_outside_region"):
        check_physical_successors(_context(), {"transfer": {"kind": "direct_successors",
                                                           "successors": [{"linear": "0x11204"}]}})


def test_physical_call_continuation_cannot_match_only_after_word_wrapping():
    """Malformed transfer metadata cannot alias a distant continuation block."""
    block = {"source": {"jumpkind": "Ijk_Call", "transfer": {
        "kind": "direct_call", "target": {"linear": "0x1230"},
        "fallthrough": {"linear": "0x11204"},
    }}}
    state = {"control_ip": {"op": "const", "width": 32, "value": "0x1230"}}
    with pytest.raises(Real16CallRefusal, match="successor_outside_region"):
        checked_call_site(_context(), 0, block, state)


@pytest.mark.parametrize("operation,left,right,width,expected", [
    ("add", 0xFFFF, 1, 16, 0), ("sub", 0, 1, 16, 0xFFFF),
    ("add", 0xFFFFFFFF, 1, 32, 0), ("add", 0x1209, 0x27, 32, 0x1230),
])
def test_literal_control_arithmetic_has_exact_modular_width(operation, left, right, width, expected):
    term = {"op": operation, "width": width, "args": [
        {"op": "const", "width": width, "value": hex(left)},
        {"op": "const", "width": width, "value": hex(right)},
    ]}
    assert constant_bitvector(term) == (expected, width)
    term["args"][0]["width"] = 8
    assert constant_bitvector(term) is None


@pytest.mark.parametrize("operation", [None, [], {}, 1])
def test_malformed_control_operator_is_unresolved(operation):
    """Malformed dynamic term boundaries cannot invent a control destination."""
    assert constant_bitvector({"op": operation, "width": 32, "args": []}) is None


def _corrupted_far32(tail: str) -> tuple[bytes, list[dict[str, object]]]:
    image = bytearray(0x400)
    caller = bytes.fromhex("ba0100669a300200001000c3")
    # Copy the low return offset into its upper word. RETF32 must consume that
    # upper word; a RETF16 after POP consumes the equal low projection instead.
    callee = bytes.fromhex("5589e58b46028946045d" + tail)
    image[0x200:0x200 + len(caller)] = caller
    image[0x330:0x330 + len(callee)] = callee
    return bytes(image), [
        _edge_function("demo.exe:caller", "caller", offset=0x200, size=len(caller)),
        _edge_function("demo.exe:callee", "callee", offset=0x330, size=len(callee)),
    ]


def test_far32_corrupted_upper_return_cannot_prove_equal_low_control(tmp_path: Path):
    documents, executions = [], []
    relocs = ((0x209, 0),)
    for tag, tail in (("oracle", "66cb"), ("candidate", "58ca0200")):
        image, functions = _corrupted_far32(tail)
        documents.append(_lower(tmp_path, image, functions, tag, relocs=relocs))
        loaded = image_from_mz_bytes(_mz_exe(image, relocs=relocs))
        entry = SegOffset(loaded.load_segment, 0x200)
        vector = Real16Vector(
            registers=(("sp", 0x100), ("flags", 2)),
            segments=(("ss", 0x7000), ("ds", entry.segment), ("es", entry.segment)),
            frame=CallerFrame(FrameKind.NEAR16, SegOffset(entry.segment, 0x8000)),
        )
        executions.append(replay(loaded, entry, vector, instruction_limit=100))
    assert executions[0].status is Real16ReplayStatus.CONTROL
    assert executions[1].status is Real16ReplayStatus.RETURNED
    compared = compare_real16_with_calls(*documents, "demo.exe:caller", timeout_ms=60000)
    assert compared["status"] == "refused", compared
    assert compared["reason"] == "return_target_unproved", compared
