"""Operand-size CALL/RET pairs prove only with full control and frame effects."""

import pytest
from tools.dosunit.tests.test_dosunit_tool import _edge_function, _mz_exe
from tools.dosunit.tests.test_real16_call_composition import _lower

from tools.dosunit.compare.real16_binary_compare import compare_binary16
from tools.dosunit.compare.real16_call_composition import compare_real16_with_calls
from tools.dosunit.runtime.real16_mz_load import image_from_mz_bytes
from tools.dosunit.runtime.real16_replay import compare_executions, replay
from tools.dosunit.runtime.real16_replay_model import (
    CallerFrame,
    FrameKind,
    Real16Agreement,
    Real16ReplayStatus,
    Real16Vector,
    SegOffset,
)


def _fixture(far, variant):
    caller = bytes.fromhex("ba0100669a300200001000c3" if far else "ba010066e827000000c3")
    ret = "66cb" if far else "66c3"
    if variant == "same":
        leaf = bytes.fromhex("89d0" + ret)
    elif variant == "equivalent":
        leaf = bytes.fromhex("9089d0" + ret)
    elif variant == "value":
        leaf = bytes.fromhex("b80200" + ret)
    else:
        assert variant == "cleanup"
        leaf = bytes.fromhex("89d066ca0200" if far else "89d066c20200")
    destination = 0x330 if far else 0x230
    image = bytearray(0x400)
    image[0x200:0x200 + len(caller)] = caller
    image[destination:destination + len(leaf)] = leaf
    functions = [
        _edge_function("demo.exe:caller", "caller", offset=0x200, size=len(caller)),
        _edge_function("demo.exe:callee", "callee", offset=destination, size=len(leaf)),
    ]
    return bytes(image), functions, ((0x209, 0),) if far else ()


@pytest.mark.parametrize("far", [False, True], ids=["near32", "far32"])
@pytest.mark.parametrize("variant,expected", [("same", "passed"), ("equivalent", "passed"), ("value", "failed"),
                                             ("cleanup", "failed")])
def test_operand32_call_composition_matches_independent_frame_execution(tmp_path, far, variant, expected):
    """Prove an equivalent edit; return value and cleanup mutations cannot pass."""
    original, functions, relocs = _fixture(far, "same")
    candidate, other_functions, _ = _fixture(far, variant)
    documents = [
        _lower(tmp_path, original, functions, "original", relocs=relocs),
        _lower(tmp_path, candidate, other_functions, "candidate", relocs=relocs),
    ]
    compared = compare_real16_with_calls(*documents, "demo.exe:caller", timeout_ms=60000)
    assert compared["status"] == expected, compared
    images = [image_from_mz_bytes(_mz_exe(data, relocs=relocs)) for data in (original, candidate)]
    entry = SegOffset(images[0].load_segment, 0x200)
    vector = Real16Vector(
        registers=(("sp", 0x100), ("flags", 2)),
        segments=(("ss", 0x7000), ("ds", entry.segment), ("es", entry.segment)),
        frame=CallerFrame(FrameKind.NEAR16, SegOffset(entry.segment, 0x8000)),
    )
    executions = [replay(image, entry, vector, instruction_limit=100) for image in images]
    assert executions[0].status is Real16ReplayStatus.RETURNED
    assert dict(executions[0].registers)["sp"] == 0x102
    assert dict(executions[0].registers)["ax"] == 1
    agreement = compare_executions(*executions).agreement
    if variant in {"same", "equivalent"}:
        assert agreement is Real16Agreement.AGREED
    elif variant == "value":
        assert agreement is Real16Agreement.MISMATCHED
    else:
        # Cleanup shifts the outer caller's saved return too. Escaping its
        # declared code range is a replay coverage gap, not a known mismatch.
        assert agreement is not Real16Agreement.AGREED


@pytest.mark.parametrize("far", [False, True], ids=["near32", "far32"])
@pytest.mark.parametrize("variant,expected", [("equivalent", "proved"), ("value", "counterexample")])
def test_public_operand32_call_obligation(tmp_path, far, variant, expected):
    """The public ledger consumes full operand-size call effects and mutations."""
    original, functions, relocs = _fixture(far, "same")
    candidate, other_functions, _ = _fixture(far, variant)
    original_path, candidate_path = tmp_path / "original.exe", tmp_path / "candidate.exe"
    original_path.write_bytes(_mz_exe(original, relocs=relocs))
    candidate_path.write_bytes(_mz_exe(candidate, relocs=relocs))
    catalog = {"schema": "dosunit.functions.v1", "id": "functions:test", "module": "demo.exe",
               "program_kind": "mz_exe", "diagnostics": [], "functions": functions}
    report = compare_binary16(original_path, candidate_path, catalog,
                              {**catalog, "functions": other_functions}, selected=("caller",))
    assert report["status"] == expected, {"proof": report["proof"], "backend": report["backend"]}
    assert report["proof"]["verdicts"][0]["method"] == "ssa_z3_complete_call_inlining"
