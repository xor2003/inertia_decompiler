"""Regression evidence for the isolated flat32 proof adapter."""

import sys
from argparse import Namespace
from pathlib import Path
from typing import Any

import archinfo
import pytest
import pyvex

sys.path.insert(0, str(Path(__file__).parent))
from flat32_adapter import OUTPUT_REGS, REG_NAMES, S, installed
from z3cmp32 import catalog, exit_code, mapping


def lower(code: str) -> dict[str, Any] | S.LowerFailure:
    """Lower actual i386 bytes with all configured observables."""
    block = pyvex.IRSB(bytes.fromhex(code), 0x12345000, archinfo.ArchX86(), opt_level=0)
    return S._lower_irsb(block, output_regs=OUTPUT_REGS, max_assignments_per_function=512)


def document(body: dict[str, Any], module: str) -> dict[str, Any]:
    """Wrap a complete function body in the dosunit comparison schema."""
    return {
        "functions": [
            {
                "id": module,
                "function": {"id": f"{module}:f", "name": "f"},
                "part": {"kind": "block", "index": 0, "entry_delta": "0x0"},
                "entry": {"linear": "0x12345000"},
                "function_entry": {"linear": "0x12345000"},
                "source": {"jumpkind": "Ijk_Ret"},
                **body,
            }
        ]
    }


def compare(left: dict[str, Any] | S.LowerFailure, right: dict[str, Any] | S.LowerFailure) -> dict[str, Any]:
    """Use the public comparator, with actual Z3 and no binary-equality shortcut."""
    assert not isinstance(left, S.LowerFailure), left
    assert not isinstance(right, S.LowerFailure), right
    result = S.compare_ssa_documents(
        oracle=document(left, "o"),
        candidate=document(right, "c"),
        mapping_document=mapping("o", "c", ["f"]),
        enable_region_equality=False,
        enable_connectivity=False,
        enable_callee_lemmas=False,
        skip_binary_equal=False,
    )
    assert result["summary"]["total"] == 1
    return result["results"][0]


def test_partial_word_hash_and_corrupted_control() -> None:
    """Partial word hash and corrupted control."""
    with installed():
        oracle = lower("8b442404 6625fc0f 66c1e802 25ffff0000 c3")
        candidate = lower("0fb7442404 c1f802 25ff030000 c3")
        corrupt = lower("0fb7442404 c1f802 25fe030000 c3")
        assert compare(oracle, candidate)["status"] == "passed"
        assert compare(oracle, corrupt)["status"] == "failed"


def test_high_byte_write_preserves_other_bits() -> None:
    """High byte write preserves other bits."""
    with installed():
        oracle = lower("b878563412 b49a c3")
        candidate = lower("b8789a3412 c3")
        assert compare(oracle, candidate)["status"] == "passed"


def test_ccall_condition_is_pure_and_changed_operand_fails_with_exact_flag_semantics() -> None:
    """An exactly modeled x86 SUB zero test detects a changed comparison."""
    with installed():
        first = lower("83f801 0f94c0 c3")
        second = lower("83f802 0f94c0 c3")
        assert not isinstance(first, S.LowerFailure), first
        assert any(item["op"] == "summary_x86g_calculate_condition" for item in first["assignments"])
        assert compare(first, first)["status"] == "passed"
        changed = compare(first, second)
        assert changed["status"] == "failed"
        assert changed["reason"] == "observable_mismatch"


@pytest.mark.parametrize("code", ["e800000000", "85c0 7401 c3 c3", "ebfe", "cc"])
def test_incomplete_or_exceptional_control_flow_refuses(code: str) -> None:
    """A partial prefix must never become a function proof."""
    with installed():
        assert isinstance(lower(code), S.LowerFailure)


def test_return_full_width_and_stack_delta_are_observed() -> None:
    """Return full width and stack delta are observed."""
    with installed():
        ordinary = lower("c3")
        ref = ordinary["outputs"]["eip"]["ref"]
        assert next(item for item in ordinary["assignments"] if item["id"] == ref)["width"] == 32
        assert compare(ordinary, lower("c20400"))["status"] == "failed"


def test_scoped_patches_restore_on_error() -> None:
    """Scoped patches restore on error."""
    original = S.REG_BY_OFFSET
    with pytest.raises(RuntimeError), installed():
        assert S.REG_BY_OFFSET is not original
        raise RuntimeError("test")
    assert S.REG_BY_OFFSET is original


def test_rebase_and_exit_accounting() -> None:
    """Rebase and exit accounting."""
    result = catalog("c", {"f": (0x40787B, 14)}, 0)
    assert result["functions"][0]["entry"]["offset"] == "0x40787b"
    assert exit_code({"total": 0, "passed": 0, "failed": 0}) == 2
    assert exit_code({"total": 2, "passed": 1, "failed": 0}) == 2
    assert exit_code({"total": 1, "passed": 1, "failed": 0}) == 0
    assert exit_code({"total": 1, "passed": 0, "failed": 1}) == 1


def test_closed_loop_induction_and_corrupt_control() -> None:
    """Closed loop induction and corrupt control."""
    import angr
    from flat32_cfg import compare_cfg

    code = bytes.fromhex("8b442404 85c0 7403 48 75fd c3")
    changed = bytes.fromhex("8b442404 85c0 7403 40 75fd c3")
    oracle = angr.load_shellcode(code, arch="x86", load_address=0x12345000)
    candidate = angr.load_shellcode(code, arch="x86", load_address=0x23456000)
    corrupt = angr.load_shellcode(changed, arch="x86", load_address=0x23456000)
    kwargs = {
        "name": "loop",
        "oracle_range": (0x12345000, len(code)),
        "candidate_range": (0x23456000, len(code)),
        "outputs": OUTPUT_REGS,
        "timeout_ms": 10000,
    }
    assert compare_cfg(oracle, candidate, **kwargs)["status"] == "passed"
    failed_relation = compare_cfg(oracle, corrupt, **kwargs)
    assert failed_relation["status"] == "refused", failed_relation
    assert failed_relation["backend_status"] == "failed", failed_relation


def test_auto_retries_only_loop_refusal_with_bounded_cfg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The automatic path retries loops under caps and keeps failed obligations visible."""
    import angr
    import flat32_cfg
    import flat32_region
    from z3cmp32 import compare_region_mode

    monkeypatch.setattr(flat32_region, "compare_region", lambda *args, **kwargs: {
        "status": "refused", "reason": "loop_requires_inductive_proof"})
    seen: list[dict[str, object]] = []

    def bounded_compare(*args: object, **kwargs: object) -> dict[str, object]:
        seen.append(kwargs)
        return {"status": "failed", "reason": "matched_cfg_induction", "function": {"name": "f"}}

    monkeypatch.setattr(flat32_cfg, "compare_cfg", bounded_compare)
    executable = tmp_path / "sample.exe"
    executable.write_bytes(b"MZ")
    args = Namespace(output_regs="eax,edx,esp", timeout_ms=1000, oracle_exe=executable,
                     candidate_exe=executable, out_dir=tmp_path)
    part = {"function": {"name": "f"}}
    doc = {"functions": [part], "refusals": []}
    project = angr.load_shellcode(b"\xc3", arch="x86")
    report = compare_region_mode(args, doc, doc, ["f"], [],
                                 (project, project, {"f": (1, 8)}, {"f": (2, 8)}))
    assert report["summary"]["failed"] == 1
    assert report["results"][0]["reason"] == "matched_cfg_induction"
    assert seen[0]["max_blocks"] == 8
    assert seen[0]["timeout_ms"] == 250


def test_floating_point_body_is_a_refusal_not_an_exception() -> None:
    """A real x87 body must not crash integer-SSA batch processing."""
    with installed():
        assert isinstance(lower("d9ee c3"), S.LowerFailure)


def test_normalization_cannot_use_raw_ssa_identity_shortcut() -> None:
    """A changed normalization must be applied even when raw SSA bodies match."""
    with installed():
        body = lower('b834120000 c3')
        assert not isinstance(body, S.LowerFailure)
        oracle = document(body, 'o')
        candidate = document(body, 'c')
        candidate['functions'][0]['_constant_normalization'] = {0x1234: 0x4321}
        result = S.compare_ssa_documents(oracle=oracle, candidate=candidate,
            mapping_document=mapping('o', 'c', ['f']), enable_region_equality=False,
            enable_connectivity=False, enable_callee_lemmas=False, skip_binary_equal=False)
        assert result['summary']['failed'] == 1


def _region_parts(code: str, base: int, spans: list[tuple[int, int]]) -> list[dict[str, Any]]:
    """Lift exact i386 basic blocks for region proof tests."""
    import angr

    project = angr.load_shellcode(bytes.fromhex(code), arch="x86", load_address=base)
    parts: list[dict[str, Any]] = []
    for offset, size in spans:
        block = project.factory.block(base + offset, size=size, opt_level=0)
        lowered = S._lower_irsb(
            block.vex,
            output_regs=(*REG_NAMES, "ip"),
            max_assignments_per_function=2048,
        )
        assert not isinstance(lowered, S.LowerFailure), lowered
        parts.append({
            "entry": {"linear": hex(base + offset)},
            "function_entry": {"linear": hex(base)},
            "source": {"jumpkind": block.vex.jumpkind},
            **lowered,
        })
    return parts


def test_region_proves_reblocked_pe32_branch_and_detects_changed_result() -> None:
    """Whole region proof accepts a changed CFG and detects a bad return arm."""
    from flat32_region import compare_region

    oracle_code = "e3 06 b8 01 00 00 00 c3 b8 02 00 00 00 c3"
    candidate_code = "e3 08 eb 00 b8 01 00 00 00 c3 b8 02 00 00 00 c3"
    corrupt_code = "e3 08 eb 00 b8 01 00 00 00 c3 b8 03 00 00 00 c3"
    with installed(region=True):
        oracle = _region_parts(oracle_code, 0x12345000, [(0, 2), (2, 6), (8, 6)])
        candidate = _region_parts(candidate_code, 0x23456000, [(0, 2), (2, 2), (4, 6), (10, 6)])
        corrupt = _region_parts(corrupt_code, 0x23456000, [(0, 2), (2, 2), (4, 6), (10, 6)])
        equal = compare_region(oracle, candidate, outputs=("eax", "esp"), timeout_ms=3000)
        unequal = compare_region(oracle, corrupt, outputs=("eax", "esp"), timeout_ms=3000)
    assert equal["status"] == "passed"
    assert equal["oracle_blocks_composed"] == 3
    assert equal["candidate_blocks_composed"] == 4
    assert unequal["status"] == "failed"
    assert unequal["mismatches"][0]["reg"] == "eax"


def test_region_refuses_missing_successor_and_low_budget() -> None:
    """An incomplete scan or exhausted budget cannot yield a function proof."""
    from flat32_region import RegionLimits, compare_region

    with installed(region=True):
        parts = _region_parts("e3 06 b8 01 00 00 00 c3 b8 02 00 00 00 c3", 0x12345000, [(0, 2), (2, 6), (8, 6)])
        missing = compare_region(parts[:2], parts, outputs=("eax", "esp"), timeout_ms=3000)
        limited = compare_region(
            parts, parts, outputs=("eax", "esp"), timeout_ms=3000,
            limits=RegionLimits(max_blocks=2),
        )
    assert missing["status"] == "refused"
    assert missing["reason"] == "successor_outside_complete_region"
    assert limited["status"] == "refused"
    assert limited["reason"] == "region_block_limit_or_missing"


def test_region_scanner_records_full_pe32_offsets_above_64k(tmp_path: Path) -> None:
    """A high module-relative VA must not be formatted as a 16-bit IP."""
    import angr

    address = 0x120000
    exe = tmp_path / "one-block.bin"
    exe.write_bytes(b"\xc3")
    project = angr.load_shellcode(b"\xc3", arch="x86", load_address=address)
    function = {
        "id": "sample:high",
        "names": ["high"],
        "entry": {"kind": "module_relative", "offset": hex(address)},
        "size": 1,
    }
    with installed(region=True):
        parts, refusals, _ = S._lower_function(
            project=project, linked_base=0, exe_path=exe, exe_digest="test", cache_document=None,
            cache_stats={"hits": 0, "misses": 0, "writes": 0, "errors": 0},
            function=function, segment_paragraphs={}, output_regs=(*REG_NAMES, "ip"),
            source_ir="vex", max_blocks_per_function=4, max_insns_per_function=8,
            max_assignments_per_function=256, scan_limit=8, follow_call_fallthrough=False,
            max_lift_block_ms=1000,
        )
    assert refusals == []
    assert len(parts) == 1
    assert parts[0]["function_entry"]["ip"] == "0x00120000"
    assert parts[0]["entry"]["linear"] == hex(address)
