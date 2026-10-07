"""Native AIL lowering must preserve loaded call destinations above 64 KiB."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from tools.dosunit.tests.test_dosunit_tool import _edge_catalog, _mz_exe

import tools.dosunit.compare.straightline_ssa as S


@pytest.mark.parametrize("count,expected", [(4, 0xFFFF0), (32, 0), (255, 0)])
def test_call_return_evaluator_bounds_segment_shifts(count: int, expected: int) -> None:
    """Constant CS projection uses exact DWORD shifts with bounded work."""
    term = {"op": "shl", "width": 32, "args": [
        {"op": "const", "width": 32, "value": "0xffff"},
        {"op": "const", "width": 8, "value": hex(count)},
    ]}
    assert S._eval_call_return_term(term, assignments={}, input_constants={}, memo={}) == expected


def test_ail_call_keeps_full_loaded_destination(tmp_path: Path) -> None:
    segment = 0
    offset = (segment << 4) + 0x200
    image = bytearray(offset + 0x40)
    image[offset:offset + 4] = bytes.fromhex("e81d00c3")
    exe = tmp_path / "caller.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:caller", "caller", offset=0x200, size=4)
    entry = catalog["functions"][0]["entry"]
    entry["segment_para"] = hex(segment)
    entry["linear"] = hex(offset)
    documents = [S.lower_straightline_ssa_document(
        exe_path=exe, functions_catalog=catalog,
        output_regs=("ax", "sp", "control_ip", "ip"), source_ir=source,
        follow_call_fallthrough=False,
    ) for source in ("vex", "ail")]
    for document in documents:
        assert document["refusals"] == []
        caller = document["functions"][0]
        assignments = {item["id"]: item for item in caller["assignments"]}
        for name, expected in (("control_ip", offset + 0x1020), ("ip", 0x1220)):
            value = S._eval_call_return_term(
                caller["outputs"][name], assignments=assignments,
                input_constants={"cs": segment + 0x100}, memo={},
            )
            assert value == expected
        assert "memory" in caller["outputs"]


def test_ail_jump_keeps_upper_control_bits() -> None:
    target = SimpleNamespace(kind_name="Const", value=0x11220, bits=32)
    jump = SimpleNamespace(kind_name="Jump", target=target)
    block = SimpleNamespace(statements=[jump])
    lowered = S._lower_ail_block(block, output_regs=("control_ip", "ip"),
                                 max_assignments_per_function=0)
    assert not isinstance(lowered, S.LowerFailure)
    assert lowered["outputs"]["control_ip"] == {"op": "const", "width": 32, "value": "0x11220"}
    assignments = {item["id"]: item for item in lowered["assignments"]}
    assert S._eval_call_return_term(lowered["outputs"]["ip"], assignments=assignments,
                                    input_constants={}, memo={}) == 0x1220


@pytest.mark.parametrize("code", ["c3", "66c3"])
def test_ail_return_control_matches_binary_ir(tmp_path: Path, code: str) -> None:
    image = bytearray(0x240)
    instruction = bytes.fromhex(code)
    image[0x200:0x200 + len(instruction)] = instruction
    exe = tmp_path / "return.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:leaf", "leaf", offset=0x200, size=len(instruction))
    vex, ail = [S.lower_straightline_ssa_document(
        exe_path=exe, functions_catalog=catalog, output_regs=("sp", "control_ip", "ip"),
        source_ir=source,
    ) for source in ("vex", "ail")]
    assert vex["refusals"] == ail["refusals"] == []
    assert S.compare_ssa_documents(oracle=vex, candidate=ail)["summary"]["passed"] == 1
