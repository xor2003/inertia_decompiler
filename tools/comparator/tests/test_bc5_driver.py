"""Regression evidence for the bc5 flat32 region comparator seams and its --no-cache route."""

import fcntl
import json
import sys
import tempfile
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import archinfo
import pytest
import pyvex

from tools.comparator import bc5_catalog as flat32_catalog
from tools.comparator import bc5_cli as z3cmp32
from tools.comparator import verdict as flat32_verdict
from tools.comparator import verified_pe as flat32_fast_pe
from tools.comparator.bc5_catalog import Symbol, cached_lst_data_symbols, cached_lst_functions
from tools.comparator.bc5_cli import (
    REGION_DEFAULT_BLOCK_CAP,
    REGION_MAX_BLOCK_CAP,
    compare_region_mode,
    mapped_call_entries,
    region_limits,
)
from tools.comparator.bc5_compat import OUTPUT_REGS, S, installed
from tools.comparator.bc5_region import RegionLimits, RegionRefusal, compare_region, summarize
from tools.dosunit.compare import straightline_ssa


def lower(code: str, base: int = 0x401000) -> dict[str, Any]:
    """Lower actual i386 bytes under the flat32 region seams."""
    block = pyvex.IRSB(bytes.fromhex(code), base, archinfo.ArchX86(), opt_level=0)
    with installed(region=True):
        out: dict[str, Any] = S._lower_irsb(
            block, output_regs=OUTPUT_REGS, max_assignments_per_function=512
        )
    assert not isinstance(out, S.LowerFailure), f"lowering refused: {out}"
    return out


def _ops(term: Any, acc: set[str]) -> set[str]:
    if isinstance(term, dict):
        op = term.get("op")
        if isinstance(op, str):
            acc.add(op)
        for arg in term.get("args") or []:
            _ops(arg, acc)
    return acc


def body_ops(body: dict[str, Any]) -> set[str]:
    """Collect every SSA op name in a lowered body's outputs and assignments."""
    ops: set[str] = set()
    for term in body.get("outputs", {}).values():
        _ops(term, ops)
    for item in body.get("assignments", []):
        _ops(item, ops)
    return ops


def _region_parts(code: str, base: int, spans: list[tuple[int, int]]) -> list[dict[str, Any]]:
    """Lift exact i386 basic blocks as region parts for proof tests."""
    import angr

    project = angr.load_shellcode(bytes.fromhex(code), arch="x86", load_address=base)
    parts: list[dict[str, Any]] = []
    for offset, size in spans:
        block = project.factory.block(base + offset, size=size, opt_level=0)
        lowered = S._lower_irsb(
            block.vex,
            output_regs=(*OUTPUT_REGS, "ip"),
            max_assignments_per_function=2048,
        )
        assert not isinstance(lowered, S.LowerFailure), lowered
        parts.append(
            {
                "entry": {"linear": hex(base + offset)},
                "function_entry": {"linear": hex(base)},
                "source": {"jumpkind": block.vex.jumpkind},
                **lowered,
            }
        )
    return parts


def test_divmod_lowers_udiv_urem_concat_pair() -> None:
    """`xor edx,edx; div eax; ret` must reach concat(trunc(urem),trunc(udiv))."""
    ops = body_ops(lower("31 d2 f7 f0 c3"))
    assert "unsupported" not in ops
    assert {"udiv", "urem", "concat"} <= ops


def test_region_refuses_indirect_branch_boundary() -> None:
    """`jmp eax` is an unmodeled boundary, never a verdict."""
    with installed(region=True):
        oracle = _region_parts("ff e0", 0x401000, [(0, 2)])
        candidate = _region_parts("ff e0", 0x501000, [(0, 2)])
        verdict = compare_region(oracle, candidate, outputs=("eax",), timeout_ms=5000)
    assert verdict["status"] == "refused"
    assert verdict["reason"] == "indirect_or_unmodeled_branch"


def test_region_normalizes_relocation_constant_inside_solve() -> None:
    """Store-address relocation must normalize inside solving, not post-verdict."""
    with installed(region=True):
        oracle = _region_parts("c7 05 74 40 4a 00 00 00 00 00 c3", 0x401000, [(0, 11)])
        candidate = _region_parts("c7 05 00 00 5b 00 00 00 00 00 c3", 0x501000, [(0, 11)])
        raw = compare_region(oracle, candidate, outputs=("eax",), timeout_ms=5000)
        normalized = compare_region(
            oracle, candidate, outputs=("eax",), timeout_ms=5000, normalization={0x5B0000: 0x4A4074}
        )
    assert raw["status"] == "failed"
    assert normalized["status"] == "passed"


def test_flat32_repeat_movsd_lowers_summary_with_fallthrough_eip() -> None:
    """`rep movsd` must produce a summary part, not a raw back-edge ip."""
    instructions = [
        {
            "bytes": "f3a5",
            "disassembly": "rep movsd",
            "mnemonic": "rep movsd",
            "size": 2,
            "address": {"linear": "0x401000", "ip": "0x1000"},
        }
    ]
    with installed(region=True):
        transfer = S._repeat_string_transfer(instructions)
        lowered = S._lower_repeat_string_summary(
            instructions,
            output_regs=(*OUTPUT_REGS, "ecx", "edx", "ip"),
            max_assignments_per_function=2048,
        )
    assert transfer is not None and lowered is not None
    assert transfer["summary"] == "repeat_string"
    assert lowered["summary"]["kind"] == "repeat_string"
    assert lowered["outputs"]["eip"] == {"op": "const", "value": "0x401002", "width": 32}
    assert lowered["outputs"]["ip"]["op"] == "const"
    assert {"name": "d", "width": 32} in lowered["inputs"]
    assignments = {item["id"]: item for item in lowered["assignments"]}

    def resolved_op(reg: str) -> str:
        term = lowered["outputs"][reg]
        if "ref" in term:
            return str(assignments[term["ref"]]["op"])
        return str(term["op"])

    for reg in ("ecx", "esi", "edi"):
        assert resolved_op(reg).startswith("summary_rep_movs32")
    assert resolved_op("memory").startswith("summary_rep_movs32")


def test_region_rewrites_div_fault_exit_as_trap_terminal() -> None:
    """A mid-block `div` fault exit composes as a trap terminal, not a missing block."""
    # xor edx,edx; mov ebx,12; mov eax,1; div ebx; ret
    good = "31 d2 bb 0c 00 00 00 b8 01 00 00 00 f7 f3 c3"
    # identical shape but the divisor is 0 — guaranteed #DE divergence
    div0 = "31 d2 bb 00 00 00 00 b8 01 00 00 00 f7 f3 c3"
    with installed(region=True):
        oracle = _region_parts(good, 0x401000, [(0, 15)])
        candidate = _region_parts(good, 0x501000, [(0, 15)])
        trapping = _region_parts(div0, 0x501000, [(0, 15)])
    assert oracle[0].get("trap_exits"), "div fault exit must be recorded"
    with installed(region=True):
        equal = compare_region(oracle, candidate, outputs=("eax", "edx"), timeout_ms=5000)
        divergent = compare_region(oracle, trapping, outputs=("eax", "edx"), timeout_ms=5000)
    assert equal["status"] == "passed"
    assert divergent["status"] == "failed"


def test_executable_section_bounds_admits_image_code_only() -> None:
    """Region successors are admitted on executable image bytes, not lst extents."""
    import angr

    from tools.comparator.bc5_compat import executable_section_bounds

    project = angr.load_shellcode(b"\x90\xc3", arch="x86", load_address=0x401000)
    assert executable_section_bounds(project=project, function_base=0x401000, successor=0x401001)
    assert not executable_section_bounds(project=project, function_base=0x401000, successor=0x900000)


def test_region_composes_branchy_acyclic_body() -> None:
    """Reblocked conditional bodies compose both arms and merge state."""
    oracle_code = "e3 06 b8 01 00 00 00 c3 b8 02 00 00 00 c3"
    candidate_code = "e3 08 eb 00 b8 01 00 00 00 c3 b8 02 00 00 00 c3"
    corrupt_code = "e3 08 eb 00 b8 01 00 00 00 c3 b8 03 00 00 00 c3"
    with installed(region=True):
        oracle = _region_parts(oracle_code, 0x401000, [(0, 2), (2, 6), (8, 6)])
        candidate = _region_parts(candidate_code, 0x501000, [(0, 2), (2, 2), (4, 6), (10, 6)])
        corrupt = _region_parts(corrupt_code, 0x501000, [(0, 2), (2, 2), (4, 6), (10, 6)])
        equal = compare_region(oracle, candidate, outputs=("eax", "esp"), timeout_ms=5000)
        unequal = compare_region(oracle, corrupt, outputs=("eax", "esp"), timeout_ms=5000)
    assert equal["status"] == "passed"
    assert equal["oracle_blocks_composed"] == 3
    assert equal["candidate_blocks_composed"] == 4
    assert unequal["status"] == "failed"
    assert unequal["mismatches"][0]["reg"] == "eax"


def test_region_scanner_cap_is_shared_with_composition_boundary() -> None:
    """The default stays bounded; opt-in accepts 256 but refuses block 257."""
    assert region_limits().max_blocks == REGION_DEFAULT_BLOCK_CAP == 128
    limits = region_limits(REGION_MAX_BLOCK_CAP)
    assert REGION_MAX_BLOCK_CAP == 256
    assert limits.max_blocks == REGION_MAX_BLOCK_CAP
    assert limits.max_compositions == 256
    with pytest.raises(RegionRefusal, match="region_block_limit_or_missing"):
        summarize([{}] * 257, outputs=("eax",), limits=limits)


def test_call_entry_resolution_uses_full_mapped_catalog_and_refuses_alias_ambiguity() -> None:
    """A shard can resolve unselected callees, but ambiguous aliases are not trusted."""
    boundaries = {"sub_caller": (0x401000, 0x401020), "sub_callee": (0x402000, 0x402020),
                  "sub_alias": (0x402000, 0x402020), "data_label": (0x403000, 0x403010)}
    symbols = {"sub_caller": Symbol(0x501000, 32, "T"),
               "sub_callee": Symbol(0x502000, 32, "T"),
               "sub_alias": Symbol(0x502000, 32, "T"),
               "data_label": Symbol(0x503000, 16, "D")}
    oracle, candidate = mapped_call_entries(boundaries, symbols, 0)
    assert oracle == {0x401000: "sub_caller"}
    assert candidate == {0x501000: "sub_caller"}


def test_listing_cache_preserves_bounds_and_data_and_invalidates_on_change(tmp_path: Path) -> None:
    """Parsed sidecars can be shared without carrying stale proof addresses."""
    listing = tmp_path / "module.lst"
    cache_dir = tmp_path / "cache"
    listing.write_text(
        "CODE:00401000 sub_401000 proc near\n"
        "CODE:00401002 sub_401000 endp\n"
        "CODE:00402000 jump_table\tdd offset sub_401000\n"
        "CODE:00402004                 mov eax, dword_402100\n"
        "DATA:00403000 data_label db 0\n"
    )
    assert cached_lst_functions(listing, cache_dir) == {"sub_401000": (0x401000, 0x401002)}
    assert cached_lst_data_symbols(listing, cache_dir) == {
        "jump_table": 0x402000, "data_label": 0x403000
    }
    assert cached_lst_functions(listing, cache_dir) == {"sub_401000": (0x401000, 0x401002)}
    data_cache = next(cache_dir.glob("lst-v*-data-*.json"))
    altered = json.loads(data_cache.read_text())
    altered["entries"]["jump_table"] = 0xDEADBEEF
    data_cache.write_text(json.dumps(altered))
    assert cached_lst_data_symbols(listing, cache_dir)["jump_table"] == 0x402000
    data_cache.write_text("broken cache")
    assert cached_lst_data_symbols(listing, cache_dir)["jump_table"] == 0x402000
    listing.write_text("CODE:00401010 sub_new proc near\nCODE:00401011 sub_new endp\n")
    assert cached_lst_functions(listing, cache_dir) == {"sub_new": (0x401010, 0x401011)}
    assert cached_lst_data_symbols(listing, cache_dir) == {}


def test_listing_cache_rejects_file_changed_during_parse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A racing sidecar edit cannot seed a cache under the old content hash."""
    listing = tmp_path / "module.lst"
    listing.write_text("CODE:00401000 sub_old proc near\nCODE:00401001 sub_old endp\n")
    original_parser = flat32_catalog.lst_functions

    def parse_then_change(path: Path) -> dict[str, tuple[int, int]]:
        result = original_parser(path)
        path.write_text("CODE:00402000 sub_new proc near\nCODE:00402001 sub_new endp\n")
        return result

    monkeypatch.setattr(flat32_catalog, "lst_functions", parse_then_change)
    with pytest.raises(RuntimeError, match="listing changed while parsing"):
        cached_lst_functions(listing, tmp_path / "cache")


def test_region_refuses_missing_successor_and_low_budget() -> None:
    """Partial scans and tiny term budgets refuse instead of comparing halves."""
    code = "e3 06 b8 01 00 00 00 c3 b8 02 00 00 00 c3"
    with installed(region=True):
        oracle = _region_parts(code, 0x401000, [(0, 2), (2, 6), (8, 6)])
        missing = oracle[:1]
        incomplete = compare_region(oracle, missing, outputs=("eax",), timeout_ms=5000)
        tight = compare_region(
            oracle,
            oracle,
            outputs=("eax",),
            timeout_ms=5000,
            limits=RegionLimits(max_term_nodes=1),
        )
    assert incomplete["status"] == "refused"
    assert incomplete["reason"] == "successor_outside_complete_region"
    assert tight["status"] == "refused"
    assert tight["reason"] == "region_expression_limit"


def test_abi_terms_equal_deep_ite_dag() -> None:
    """Shared-subterm ite DAGs must compare in node count, not path count."""
    leaf: dict[str, Any] = {"op": "const", "value": "0x00000001", "width": 32}
    shared = leaf
    for _ in range(64):
        shared = {"op": "ite", "width": 32, "args": [leaf, shared, leaf]}
    assert S._abi_terms_equal(shared, dict(shared), {})
    other = {"op": "ite", "width": 32, "args": [leaf, leaf, leaf]}
    assert not S._abi_terms_equal(shared, other, {})


def _call_parts(
    call_target: int,
    base: int,
    fallthrough_code: str = "c3",
) -> list[dict[str, Any]]:
    """Lift a real i386 `call rel32; <fallthrough>` region with scanner transfer metadata."""
    rel = (call_target - (base + 5)) & 0xFFFFFFFF
    code = "e8" + rel.to_bytes(4, "little").hex() + fallthrough_code
    spans = [(0, 5), (5, len(bytes.fromhex(fallthrough_code)))]
    parts = _region_parts(code, base, spans)
    parts[0]["source"]["transfer"] = {
        "kind": "direct_call",
        "jumpkind": "Ijk_Call",
        "target": {"raw": hex(call_target), "low16": hex(call_target & 0xFFFF)},
        "fallthrough": {"linear": hex(base + 5), "low16": hex((base + 5) & 0xFFFF)},
    }
    return parts


def test_region_refuses_calls_without_resolver() -> None:
    """A call block still refuses when no callee evidence policy is installed."""
    with installed(region=True):
        oracle = _call_parts(0x402000, 0x401000)
        candidate = _call_parts(0x402000, 0x401000)
        verdict = compare_region(oracle, candidate, outputs=("eax", "esp"), timeout_ms=5000)
    assert verdict["status"] == "refused"
    assert verdict["reason"] == "call_or_exception_boundary"


def test_region_paired_direct_calls_are_conditional() -> None:
    """Same-name callees yield CONDITIONAL with named pairs, never PASSED."""
    oracle_resolver = {0x402000: "sub_402000"}.get
    candidate_resolver = {0x502000: "sub_402000"}.get
    with installed(region=True):
        oracle = _call_parts(0x402000, 0x401000)
        candidate = _call_parts(0x502000, 0x501000)
        verdict = compare_region(
            oracle,
            candidate,
            outputs=("eax", "esp"),
            timeout_ms=5000,
            call_resolver_oracle=oracle_resolver,
            call_resolver_candidate=candidate_resolver,
        )
    assert verdict["status"] == "conditional"
    assert verdict["reason"] == "paired_call_assumptions"
    assert verdict["paired_calls"] == 1
    assert verdict["assumptions"]["kind"] == "paired_post_call_state_equality"
    pair = verdict["assumptions"]["paired_callees"][0]
    assert pair["callee"] == "sub_402000"
    assert pair["oracle_target"] == "0x402000"
    assert pair["candidate_target"] == "0x502000"


def test_paired_call_conditional_also_records_relocation_assumption(tmp_path: Path) -> None:
    """A caller proof using both assumptions names both in one verdict."""
    oracle_exe = tmp_path / "oracle.exe"
    candidate_exe = tmp_path / "candidate.exe"
    oracle_exe.write_bytes(b"MZ")
    candidate_exe.write_bytes(b"MZ")
    args = Namespace(output_regs="eax,esp", timeout_ms=5000, region_max_blocks=128,
                     oracle_exe=oracle_exe, candidate_exe=candidate_exe)
    with installed(region=True):
        oracle_parts = _call_parts(0x402000, 0x401000)
        candidate_parts = _call_parts(0x502000, 0x501000)
        for part in (*oracle_parts, *candidate_parts):
            part["function"] = {"name": "caller"}
        report = compare_region_mode(
            args, {"functions": oracle_parts, "refusals": []},
            {"functions": candidate_parts, "refusals": []}, ["caller"],
            existing_results=[], relocation={0x900000: 0x800000},
            call_entries=({0x402000: "sub_callee"}, {0x502000: "sub_callee"}),
        )
    verdict = report["results"][0]
    assert verdict["status"] == "conditional"
    assert verdict["assumptions"]["kind"] == "paired_post_call_state_equality"
    assert verdict["assumptions"]["constant_relocation_count"] == 1


def test_region_refuses_wrong_or_unmapped_call_target() -> None:
    """A different callee name or an unmapped target must refuse, never equalize."""
    with installed(region=True):
        oracle = _call_parts(0x402000, 0x401000)
        wrong_name = _call_parts(0x502000, 0x501000)
        unmapped = _call_parts(0x50F000, 0x501000)
        resolved = {0x402000: "sub_402000", 0x502000: "sub_402000"}.get
        mismatched = compare_region(
            oracle,
            wrong_name,
            outputs=("eax", "esp"),
            timeout_ms=5000,
            call_resolver_oracle=resolved,
            call_resolver_candidate={0x502000: "sub_503000"}.get,
        )
        unknown = compare_region(
            oracle,
            unmapped,
            outputs=("eax", "esp"),
            timeout_ms=5000,
            call_resolver_oracle=resolved,
            call_resolver_candidate=resolved,
        )
    assert mismatched["status"] == "refused"
    assert mismatched["reason"] == "unmatched_call_order"
    assert unknown["status"] == "refused"
    assert unknown["reason"] == "call_target_unmapped"


def test_region_call_preserved_caller_mismatch_fails() -> None:
    """Havoced callee state must not hide a real post-call caller divergence."""
    resolved = {0x402000: "sub_402000", 0x502000: "sub_402000"}.get
    with installed(region=True):
        oracle = _call_parts(0x402000, 0x401000)
        corrupt = _call_parts(0x502000, 0x501000, fallthrough_code="b800000000c3")
        verdict = compare_region(
            oracle,
            corrupt,
            outputs=("eax", "esp"),
            timeout_ms=5000,
            call_resolver_oracle=resolved,
            call_resolver_candidate=resolved,
        )
    assert verdict["status"] == "refused"
    assert verdict["reason"] == "paired_call_model_counterexample"
    assert verdict["backend_status"] == "failed"


def test_installed_region_scope_restores() -> None:
    """Installation preserves shared scan admission; the driver passes it explicitly."""
    sentinel = S._can_add_dynamic_successor_range
    with installed(region=True):
        assert S._can_add_dynamic_successor_range is sentinel
    assert S._can_add_dynamic_successor_range is sentinel


LISTING = (
    "CODE:00401000 sub_401000 proc near\n"
    "CODE:00401002 sub_401000 endp\n"
    "CODE:00402000 jump_table\tdd offset sub_401000\n"
    "DATA:00403000 data_label db 0\n"
)


def _run_main(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, extra: list[str]) -> Namespace:
    """Route one parse through main() with the proof body stubbed out."""
    captured: dict[str, Namespace] = {}
    registers = S.REG_BY_OFFSET
    lowerer = S._lower_function
    finisher = S._finish_irsb_lowering

    def fake_compare(args: Namespace) -> dict[str, Any]:
        assert S.REG_BY_OFFSET is registers
        assert S._lower_function is lowerer
        assert S._finish_irsb_lowering is finisher
        captured["args"] = args
        return {"summary": flat32_verdict.summarize([]), "results": []}

    monkeypatch.setattr(z3cmp32, "compare", fake_compare)
    monkeypatch.setattr(sys, "argv", [
        "z3cmp32.py",
        "--oracle-exe", str(tmp_path / "oracle.exe"),
        "--oracle-lst", str(tmp_path / "oracle.lst"),
        "--candidate-exe", str(tmp_path / "candidate.exe"),
        "--functions", "sub_401000",
        "--out-dir", str(tmp_path / "out"),
        *extra,
    ])
    # Stubbed compare produces no passed obligations; routing is what is asserted.
    z3cmp32.main()
    return captured["args"]


def test_no_cache_maps_single_owner_to_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """--no-cache must set the one cache owner to None for every consumer."""
    args = _run_main(monkeypatch, tmp_path, ["--no-cache"])
    assert args.cache_dir is None


def test_no_cache_overrides_explicit_cache_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The dosunit ssa pattern applies: --no-cache wins over --cache-dir."""
    args = _run_main(monkeypatch, tmp_path, ["--cache-dir", str(tmp_path / "c"), "--no-cache"])
    assert args.cache_dir is None


def test_default_cache_dir_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without --no-cache the existing default and an explicit dir pass through."""
    args = _run_main(monkeypatch, tmp_path, [])
    assert args.cache_dir == Path("/tmp/z3bcc-vexcache")
    args = _run_main(monkeypatch, tmp_path, ["--cache-dir", str(tmp_path / "kept")])
    assert args.cache_dir == tmp_path / "kept"


def test_load32_verified_none_loads_without_cache_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cache_dir=None returns the plain load and touches no cache artifact."""
    exe = tmp_path / "m.exe"
    exe.write_bytes(b"MZ" + b"\0" * 64)
    sentinel = object()
    monkeypatch.setattr(flat32_fast_pe, "load32", lambda *a, **k: sentinel)
    monkeypatch.setattr(
        flat32_fast_pe, "_read_certificate", lambda _p: pytest.fail("cache read reached")
    )
    monkeypatch.setattr(
        flat32_fast_pe, "_write_certificate", lambda *_a: pytest.fail("cache write reached")
    )
    assert flat32_fast_pe.load32_verified(exe, None) is sentinel
    assert [p.name for p in tmp_path.iterdir()] == ["m.exe"]


def test_cached_listing_none_parses_directly_without_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cache_dir=None returns the parse and never opens a lock or cache file."""
    listing = tmp_path / "module.lst"
    listing.write_text(LISTING)
    monkeypatch.setattr(
        fcntl, "flock", lambda *_a, **_k: pytest.fail("cache lock reached")
    )
    monkeypatch.setattr(
        tempfile, "NamedTemporaryFile",
        lambda *_a, **_k: pytest.fail("cache write reached"),
    )
    assert cached_lst_functions(listing, None) == {"sub_401000": (0x401000, 0x401002)}
    assert cached_lst_data_symbols(listing, None) == {
        "jump_table": 0x402000, "data_label": 0x403000
    }
    assert [p.name for p in tmp_path.iterdir()] == ["module.lst"]


def test_cached_listing_enabled_path_unchanged(tmp_path: Path) -> None:
    """An explicit cache dir still writes and reuses lst-v* artifacts."""
    listing = tmp_path / "module.lst"
    listing.write_text(LISTING)
    cache_dir = tmp_path / "cache"
    assert cached_lst_functions(listing, cache_dir) == {"sub_401000": (0x401000, 0x401002)}
    assert len(list(cache_dir.glob("lst-v*-functions-*.json"))) == 1
    assert cached_lst_data_symbols(listing, cache_dir)["data_label"] == 0x403000
    assert len(list(cache_dir.glob("lst-v*-data-*.json"))) == 1


def test_lower_document_none_never_touches_vex_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lowering layer already honors cache_dir=None with zero cache I/O."""
    exe = tmp_path / "prog.exe"
    exe.write_bytes(b"\x90\xc3")
    project = SimpleNamespace(
        filename=str(exe),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x400000)),
    )
    monkeypatch.setattr(
        straightline_ssa, "_load_vex_cache", lambda **_kw: pytest.fail("vex cache read reached")
    )
    monkeypatch.setattr(
        straightline_ssa, "_save_vex_cache", lambda **_kw: pytest.fail("vex cache write reached")
    )
    monkeypatch.setattr(
        straightline_ssa, "_lower_function", lambda **_kw: ([], [], 0)
    )
    catalog = {
        "functions": [{
            "id": "oracle:sub_1", "names": ["sub_1"], "return_kind": "near", "size": 2,
            "entry": {"kind": "module_relative", "linear": "0x401000", "offset": "0x1000"},
        }]
    }
    document = straightline_ssa.lower_straightline_ssa_document(
        exe_path=exe, functions_catalog=catalog, cache_dir=None, lifter_project=project,
    )
    assert document["parameters"]["cache_dir"] is None
    assert document["counters"]["lifter_cache_hits"] == 0
    assert document["counters"]["lifter_cache_writes"] == 0
    assert document["counters"]["functions_refused"] == 1
