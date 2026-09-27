"""Regression evidence for the bc5 flat32 region comparator seams."""

import sys
from pathlib import Path
from typing import Any

import archinfo
import pyvex

sys.path.insert(0, str(Path(__file__).parent))
from flat32_adapter import OUTPUT_REGS, S, installed
from flat32_region import RegionLimits, compare_region


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


def test_installed_region_scope_restores() -> None:
    """The adapter patch boundary must restore every replaced seam."""
    sentinel = S._can_add_dynamic_successor_range
    with installed(region=True):
        assert S._can_add_dynamic_successor_range is not sentinel
    assert S._can_add_dynamic_successor_range is sentinel
