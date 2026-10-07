"""Native conditional boundaries retain fallthrough writes and unsafe effects."""
from __future__ import annotations

import copy
from pathlib import Path

import angr
import pytest
import pyvex
from tools.dosunit.tests.test_flat32_comparator_lane import BASE, _compare_calls, _driver_lane

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import CallCompositionRefusal
from tools.dosunit.compare.flat32_call_lowering import _check_exits


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("changed_store", [False, True])
def test_jecxz_keeps_taken_and_store_fallthrough_paths(driver: str, changed_store: bool) -> None:
    """A skipped store is optional; changing its value on the other path matters."""
    original = "e302 8907 c3"  # JECXZ skips MOV [EDI],EAX and reaches RET.
    candidate = "e302 8917 c3" if changed_store else original
    with _driver_lane(driver) as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: 5}, candidate_functions={BASE: 5},
            outputs=lane.adapter.OUTPUT_REGS)
    assert result["status"] == ("failed" if changed_store else "passed"), result


def _scan_region(code: str, tmp_path: Path) -> list[dict[str, object]]:
    """Scan complete i386 bytes through the production region SSA entry point."""
    binary = bytes.fromhex(code)
    project = angr.load_shellcode(binary, arch="x86", load_address=BASE)
    parts, refusals, _ = S._lower_function(
        project=project, linked_base=0, exe_path=tmp_path / "unused.bin", exe_digest="test",
        cache_document=None, cache_stats={"hits": 0, "misses": 0, "writes": 0, "errors": 0},
        function={"id": "f", "names": ["f"], "entry": {"kind": "module_relative", "offset": hex(BASE)},
                  "size": len(binary)},
        segment_paragraphs={}, output_regs=("eax", "esp", "eip"), source_ir="vex",
        max_blocks_per_function=8, max_insns_per_function=32, max_assignments_per_function=512,
        scan_limit=len(binary), follow_call_fallthrough=False, max_lift_block_ms=1000,
    )
    assert not refusals, refusals
    return parts


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_region_scanner_reblocks_conditional_before_return(tmp_path: Path, driver: str) -> None:
    """A conditional prefix and its store fallthrough cannot merge into one return."""
    with _driver_lane(driver) as lane, lane.adapter.installed(region=True):
        original = _scan_region("e3 02 89 07 c3", tmp_path)
        changed = _scan_region("e3 02 89 17 c3", tmp_path)
        assert [part["source"]["jumpkind"] for part in original] == ["Ijk_Boring", "Ijk_Ret", "Ijk_Ret"]
        equal = lane.region.compare_region(original, original, outputs=("eax", "esp"), timeout_ms=3000)
        unequal = lane.region.compare_region(original, changed, outputs=("eax", "esp"), timeout_ms=3000)
    assert equal["status"] == "passed", equal
    assert unequal["status"] == "failed", unequal


@pytest.mark.parametrize("exit_count", [None, False, 1])
def test_return_alias_requires_native_zero_exit_evidence(tmp_path: Path, exit_count: object) -> None:
    """Missing or malformed evidence cannot turn an incoming branch alias into a return."""
    with _driver_lane("msc8") as lane, lane.adapter.installed(region=True):
        parts = _scan_region("e3028907c3", tmp_path)
        legacy = copy.deepcopy(parts)
        for part in legacy:
            if part["source"]["jumpkind"] == "Ijk_Ret":
                part["source"]["conditional_exit_count"] = exit_count
        result = lane.region.compare_region(legacy, legacy, outputs=("eax", "esp"), timeout_ms=3000)
    assert result["status"] == "refused", result


@pytest.mark.parametrize("changed", [False, True])
def test_byte_listing_bounds_do_not_decode_alignment_suffix(changed: bool) -> None:
    """Byte bounds remove a false catalog overlap without masking a changed callee."""
    prefix = "e8 0b000000 c3 909090 8da42400000000"
    original = prefix + " 83c001 c3 90909090"
    candidate = prefix + (" 83c002 c3 90909090" if changed else " 83c001 c3 90909090")
    with _driver_lane("msc8") as lane:
        project = angr.load_shellcode(bytes.fromhex(candidate), arch="x86", load_address=BASE)
        end_kind = lane.catalog.ListingEndKind
        instruction_size = lane.catalog.listing_size(project, BASE, BASE + 15, end_kind.INSTRUCTION)
        byte_size = lane.catalog.listing_size(project, BASE, BASE + 15, end_kind.BYTE)
        assert instruction_size > byte_size == 16
        old = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: 16, BASE + 16: 4},
            candidate_functions={BASE: instruction_size, BASE + 16: 4})
        new = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: 16, BASE + 16: 4},
            candidate_functions={BASE: byte_size, BASE + 16: 4})
    assert old["status"] == "refused" and old["reason"] == "overlapping_function_ranges", old
    assert new["status"] == ("failed" if changed else "passed"), new


def test_native_successors_preserve_low_flat_addresses() -> None:
    """Flat targets below 64 KiB retain literal destinations rather than DOS aliases."""
    project = angr.load_shellcode(bytes.fromhex("e3028907c3"), arch="x86", load_address=0xFFF0)
    from tools.dosunit.architectures.flat32_cfg_lifting import lift_cfg_block

    block = lift_cfg_block(project, 0xFFF0, 5)
    assert S._ssa_block_successors(block, []) == [0xFFF4, 0xFFF2]


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_native_repeat_summary_survives_control_reblocking(tmp_path: Path, driver: str) -> None:
    """The existing typed REP summary owns its internal conditional effects."""
    with _driver_lane(driver) as lane, lane.adapter.installed(region=True):
        original = _scan_region("f3a4c3", tmp_path)
        changed = _scan_region("f3a4c20400", tmp_path)
        equal = lane.region.compare_region(original, original, outputs=("eax", "esp"), timeout_ms=3000)
        unequal = lane.region.compare_region(original, changed, outputs=("eax", "esp"), timeout_ms=3000)
    assert equal["status"] == "passed", equal
    assert unequal["status"] == "failed", unequal


def test_effect_inside_exiting_instruction_is_still_refused() -> None:
    """Splitting later instructions must not admit effects after this Exit."""
    project = angr.load_shellcode(bytes.fromhex("e300"), arch="x86", load_address=BASE)
    block = project.factory.block(BASE, size=2, opt_level=0).vex
    exit_index = next(index for index, statement in enumerate(block.statements)
                      if isinstance(statement, pyvex.stmt.Exit))
    eax_offset = project.arch.registers["eax"][0]
    block.statements.insert(exit_index + 1, pyvex.stmt.Put(pyvex.expr.Const(pyvex.const.U32(1)), eax_offset))
    with pytest.raises(CallCompositionRefusal, match="effect_after_conditional_exit"):
        _check_exits(block, project.arch.ip_offset)


def test_native_division_fault_edge_is_still_refused() -> None:
    """Conditional control support does not erase native exception outcomes."""
    project = angr.load_shellcode(bytes.fromhex("f7f1c3"), arch="x86", load_address=BASE)
    block = project.factory.block(BASE, size=3, opt_level=0).vex
    with pytest.raises(CallCompositionRefusal, match="exception_edge"):
        _check_exits(block, project.arch.ip_offset)
