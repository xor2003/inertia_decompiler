"""Regression evidence for the reblocked flat32 CFG superblock proof."""

from typing import Any

import angr
import pytest

from tools.comparator.abi import DEFAULT_OUTPUT_REGS as OUTPUT_REGS
from tools.comparator.verdict import Status
from tools.dosunit.compare.flat32_cfg_regions import compare_reblocked_cfg

ORACLE_BASE = 0x12345000
CANDIDATE_BASE = 0x23456000

# test eax,eax; jz ret / dec eax; mov [esp+4],eax; jnz body / ret
LOOP = "85c0 7407 48 89442404 75f9 c3"
# Same loop with the body split by an inserted `jmp +0` chain link.
CHAIN_LOOP = "85c0 7409 48 eb00 89442404 75f7 c3"
# Same loop with the head split by an inserted `jmp +0` link.
CHAIN_HEAD = "85c0 eb00 7407 48 89442404 75f9 c3"
# Semantic corruptions of LOOP with the same superblock graph shape.
GUARD_CORRUPT = "85db 7407 48 89442404 75f9 c3"  # test ebx,ebx not eax
UPDATE_CORRUPT = "85c0 7407 40 89442404 75f9 c3"  # inc not dec
STORE_CORRUPT = "85c0 7407 48 89442408 75f9 c3"  # [esp+8] not [esp+4]
RETURN_CORRUPT = "85c0 7407 48 89442404 75f9 c20400"  # ret 4 not ret
# mov ds,eax prologue: different segment state in the same graph shape.
SEGMENT_CHANGED = "8ed8 85c0 7409 48 eb00 89442404 75f7 c3"
# gs:-prefixed store lowers to a fault-check exit: outside this slice.
FAULT_EDGE = "85c0 740a 48 eb00 6589442404 75f6 c3"
# Unconditional back-jump: the loop exit edge is gone, arity differs.
SHAPE_CORRUPT = "85c0 7407 48 89442404 ebf9 c3"


def _compare(oracle_code: str, candidate_code: str) -> dict[str, Any]:
    oracle = angr.load_shellcode(bytes.fromhex(oracle_code), arch="x86", load_address=ORACLE_BASE)
    candidate = angr.load_shellcode(bytes.fromhex(candidate_code), arch="x86", load_address=CANDIDATE_BASE)
    return compare_reblocked_cfg(
        (oracle, candidate),
        (ORACLE_BASE, len(bytes.fromhex(oracle_code))),
        (CANDIDATE_BASE, len(bytes.fromhex(candidate_code))),
        OUTPUT_REGS,
        10000,
    )


def test_unchanged_loop_proves() -> None:
    """Identical loop bodies at different load bases prove equal."""
    result = _compare(LOOP, LOOP)
    assert result["status"] == "passed", result
    assert result["reason"] == "reblocked_cfg_induction"


def test_inserted_jmp_chain_proves() -> None:
    """A candidate split by `jmp +0` composes to the same superblock relation."""
    result = _compare(LOOP, CHAIN_LOOP)
    assert result["status"] == "passed", result
    members = [entry["candidate"] for entry in result["superblock_pairs"]]
    assert any(len(member) > 1 for member in members)


def test_split_head_and_body_prove() -> None:
    """Reblocking is symmetric: splitting the loop head also proves."""
    assert _compare(LOOP, CHAIN_HEAD)["status"] == "passed"
    assert _compare(CHAIN_HEAD, LOOP)["status"] == "passed"


@pytest.mark.parametrize(
    "candidate",
    [GUARD_CORRUPT, UPDATE_CORRUPT, STORE_CORRUPT, RETURN_CORRUPT, SEGMENT_CHANGED],
    ids=["guard", "update", "store", "return", "segment"],
)
def test_corrupted_loop_fails(candidate: str) -> None:
    """Changed guard, update, store address, segment or return fails."""
    result = _compare(LOOP, candidate)
    assert result["status"] is Status.REFUSED, result
    assert any(row["status"] is Status.FAILED for row in result["block_verdicts"]), result


def test_self_jmp_chain_cycle_refuses() -> None:
    """A pure `jmp $` cannot be collapsed away or turned into a terminal."""
    result = _compare("ebfe", "ebfe")
    assert result["status"] == "refused", result
    assert result["reason"] == "unconditional_chain_cycle"


def test_fault_checked_segment_prefix_refuses() -> None:
    """A gs: store is a fault edge under VEX; it refuses, it cannot pass."""
    result = _compare(LOOP, FAULT_EDGE)
    assert result["status"] == "refused", result
    assert result["reason"] == "exception_edge"


def test_graph_shape_mismatch_refuses() -> None:
    """Dropping the loop exit changes arity; pairing refuses the graph."""
    result = _compare(LOOP, SHAPE_CORRUPT)
    assert result["status"] == "refused", result
    assert result["reason"] in {"cfg_shape_mismatch", "unconditional_chain_cycle"}


@pytest.mark.parametrize("code", ["e800000000", "ffe0"], ids=["call", "indirect_jump"])
def test_calls_and_indirect_edges_refuse(code: str) -> None:
    """Calls and indirect transfers stay outside this slice."""
    assert _compare(code, code)["status"] == "refused"
