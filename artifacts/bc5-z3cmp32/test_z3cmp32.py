"""Regression evidence for the bc5 flat32 region comparator seams."""

import sys
from argparse import Namespace
from pathlib import Path
from typing import Any

import archinfo
import pytest
import pyvex

sys.path.insert(0, str(Path(__file__).parent))
from flat32_adapter import OUTPUT_REGS, S, installed
from flat32_catalog import Symbol
from flat32_region import RegionLimits, RegionRefusal, compare_region, summarize
from z3cmp32 import (
    REGION_DEFAULT_BLOCK_CAP,
    REGION_MAX_BLOCK_CAP,
    compare_region_mode,
    mapped_call_entries,
    region_limits,
)


def lower(code: str, base: int = 0x401000) -> dict[str, Any]:
    """Lower actual i386 bytes under the flat32 region seams."""
    block = pyvex.IRSB(bytes.fromhex(code), base, archinfo.ArchX86(), opt_level=0)
    with installed(region=True):
        out = S._lower_irsb(block, output_regs=OUTPUT_REGS, max_assignments_per_function=512)
    assert not isinstance(out, S.LowerFailure), f"lowering refused: {out}"
    return out


def _ops(term: Any, acc: set[str]) -> set[str]:  # noqa: ANN401
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
    """The adapter patch boundary must restore every replaced seam."""
    sentinel = S._can_add_dynamic_successor_range
    with installed(region=True):
        assert S._can_add_dynamic_successor_range is not sentinel
    assert S._can_add_dynamic_successor_range is sentinel
