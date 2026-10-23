"""An indirect-cell retry must retain every external contract it used."""
import struct
from dataclasses import replace
from pathlib import Path

import pytest

from tools.dosunit.architectures.flat32_loader import load_flat32_project
from tools.dosunit.compare.flat32_call_composition import compare_functions_with_calls
from tools.dosunit.compare.flat32_external_call import ExternalMemoryAccess
from tools.dosunit.tests.test_flat32_comparator_lane import DriverLane
from tools.dosunit.tests.test_flat32_external_binding import CONTRACT
from tools.dosunit.tests.test_flat32_loop_calls import BASE as LOOP_BASE
from tools.dosunit.tests.test_flat32_loop_calls import CALLER, CALLER_SIZE, _compare_loop_calls
from tools.dosunit.tests.test_pe32_import_service import ENTRY, IAT_SLOT, pe32_import_bytes

pytestmark = [pytest.mark.ssa_z3, pytest.mark.runtime]
pytest_plugins = ["test_flat32_comparator_lane"]


def test_loop_cutpoint_cannot_assume_initial_callback_cell(lane: DriverLane) -> None:
    """A zero in the image cannot silently constrain arbitrary loop memory."""
    cell = LOOP_BASE + 0x100
    callee = b"\xa1" + struct.pack("<I", cell) + bytes.fromhex("85c07402ffd0c3")
    code = (bytes.fromhex(CALLER) + callee).ljust(0x100, b"\x90") + b"\0" * 4
    functions = {LOOP_BASE: CALLER_SIZE, LOOP_BASE + CALLER_SIZE: len(callee)}
    result = _compare_loop_calls(
        lane, code.hex(), code.hex(), oracle_functions=functions, candidate_functions=functions,
    )
    assert result["status"].value == "refused", result
    assert result["reason"] == "call_indirect_target_unconstrained", result


def test_seed_retry_keeps_external_assumption(tmp_path: Path) -> None:
    """A completed external helper preceding discovery remains in the report."""
    helper, cell = ENTRY + 0x60, ENTRY + 0x100
    # A literal stack makes disjointness exact without a root ESP domain.
    # External binding must still retain its root-entry proof obligations.
    root = bytes.fromhex("bcf0ff0700e8") + struct.pack("<i", helper - (ENTRY + 10))
    root += b"\xa1" + struct.pack("<I", cell)
    root += bytes.fromhex("85c07402ffd0b82a000000c3")
    body = b"\xff\x15" + struct.pack("<I", IAT_SLOT) + b"\xc3"
    code = (root.ljust(0x60, b"\x90") + body).ljust(0x100, b"\x90") + b"\0" * 4
    oracle, candidate = tmp_path / "oracle.exe", tmp_path / "candidate.exe"
    oracle.write_bytes(pe32_import_bytes(code))
    candidate.write_bytes(pe32_import_bytes(code))
    functions = {ENTRY: len(root), helper: len(body)}
    result = compare_functions_with_calls(
        load_flat32_project(oracle), load_flat32_project(candidate),
        oracle_entry=ENTRY, candidate_entry=ENTRY,
        oracle_functions=functions, candidate_functions=functions,
        outputs=("eax",), timeout_ms=10000,
        external_contracts=(replace(CONTRACT, memory_access=ExternalMemoryAccess.NONE),),
    )
    assert result["status"] == "conditional", result
    assert result["indirect_cell_assumptions"]["obligations"]
    external = result["external_call_assumptions"]
    assert external["oracle_sites"] and external["candidate_sites"]
