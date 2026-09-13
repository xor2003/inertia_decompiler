"""Real-lifter regressions for complete typed IR CFG successors."""

from __future__ import annotations

import io
from types import SimpleNamespace

import angr
import pytest
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import IRBlock, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.block_ownership import (
    IRBlockOwnershipFailure8616,
    IRBlockSuccessorRewriteFailure8616,
    canonicalize_ir_block_ownership_8616,
)
from angr_platforms.X86_16.ir.block_successor_chain import proven_suffix_owner_chain_8616
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401


def test_real_conditional_exit_retains_taken_and_fallthrough_successors() -> None:
    project = angr.Project(
        io.BytesIO(bytes.fromhex("83fa007402eb00c3")),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000, 0x1005, 0x1007},
        info={},
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    ssa = build_x86_16_function_ssa(artifact)

    assert not artifact.refusals
    assert artifact.blocks[0].successor_addrs == (0x1005, 0x1007)
    assert ssa.predecessor_map == {
        0x1000: (),
        0x1005: (0x1000,),
        0x1007: (0x1000, 0x1005),
    }


def test_overlapping_real_blocks_assign_call_to_exact_start_owner() -> None:
    """Require one canonical CALL when CFG recovery emits overlapping blocks."""
    project = angr.Project(
        io.BytesIO(bytes.fromhex("b80100e80000c3")),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    nodes = {address: SimpleNamespace(addr=address) for address in (0x1000, 0x1003, 0x1006)}
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set=set(nodes),
        graph=SimpleNamespace(
            edges=((nodes[0x1000], nodes[0x1003]), (nodes[0x1003], nodes[0x1006]))
        ),
        info={},
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    calls = tuple(
        (block.addr, instruction.addr)
        for block in artifact.blocks
        for instruction in block.instrs
        if instruction.op == "CALL"
    )

    assert calls == ((0x1003, 0x1003),)
    assert artifact.summary["block_ownership_classified_fact_count"] > 0
    assert (
        artifact.summary["block_ownership_materialized_count"]
        == artifact.summary["block_ownership_classified_fact_count"]
    )
    assert artifact.summary["block_ownership_failure_count"] == 0


def test_overlap_without_exact_owner_decode_is_refused_and_preserved() -> None:
    """Keep an overlap when the proposed owner does not decode its instruction."""
    call = IRInstr(
        "CALL",
        None,
        (IRValue(MemSpace.CONST, const=0x2000, size=2),),
        addr=0x1003,
    )
    evidence = canonicalize_ir_block_ownership_8616(
        (
            IRBlock(0x1000, (call,), successor_addrs=(0x1003,)),
            IRBlock(0x1003),
        )
    )

    assert evidence.blocks[0].instrs == (call,)
    assert evidence.stats.materialized_count == 0
    assert evidence.stats.failure_count == 1
    assert (
        evidence.refusals[0].failure
        is IRBlockOwnershipFailure8616.CANONICAL_OWNER_MISSING_INSTRUCTION
    )


def test_overlap_prefix_retargets_identical_branch_to_canonical_suffix() -> None:
    """Make the suffix owner, not its update prefix, own branch polarity."""
    update = IRInstr("Iop_Add16", None, (), addr=0x1000)
    guard = IRInstr("CJMP", None, (), addr=0x1003)
    evidence = canonicalize_ir_block_ownership_8616(
        (
            IRBlock(0x1000, (update, guard), successor_addrs=(0x1010, 0x1020)),
            IRBlock(0x1003, (guard,), successor_addrs=(0x1010, 0x1020)),
            IRBlock(0x1010),
            IRBlock(0x1020),
        )
    )

    assert evidence.complete
    assert evidence.blocks[0].instrs == (update,)
    assert evidence.blocks[0].successor_addrs == (0x1003,)
    assert evidence.successor_stats.materialized_count == 1
    assert evidence.successor_stats.failure_count == 0
    assert evidence.successor_rewrites[0].canonical_block_addr == evidence.blocks[1].addr


def test_overlap_prefix_keeps_conflicting_successors_with_typed_refusal() -> None:
    """Refuse CFG rewiring when source and suffix edges are not identical."""
    update = IRInstr("Iop_Add16", None, (), addr=0x1000)
    guard = IRInstr("CJMP", None, (), addr=0x1003)
    evidence = canonicalize_ir_block_ownership_8616(
        (
            IRBlock(0x1000, (update, guard), successor_addrs=(0x1010, 0x1030)),
            IRBlock(0x1003, (guard,), successor_addrs=(0x1010, 0x1020)),
        )
    )

    assert evidence.complete
    assert evidence.blocks[0].successor_addrs == (0x1010, 0x1030)
    assert evidence.successor_stats.materialized_count == 0
    assert evidence.successor_stats.failure_count == 1
    assert evidence.successor_refusals[0].failure is (
        IRBlockSuccessorRewriteFailure8616.SUCCESSOR_CONFLICT
    )


def test_overlapping_real_block_chain_does_not_create_extra_branch_predecessors() -> None:
    """Splitting two prefixes must leave the compare block as the branch owner."""
    project = angr.Project(
        io.BytesIO(bytes.fromhex("b80100bb020039d87402eb00c3")),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
    )
    function = SimpleNamespace(
        addr=0x1000, block_addrs_set={0x1000, 0x1003, 0x1006, 0x100A, 0x100C}, info={},
    )
    artifact = build_x86_16_ir_function_artifact(project, function)
    ssa = build_x86_16_function_ssa(artifact)
    successors = {block.addr: block.successor_addrs for block in artifact.blocks}
    assert successors[0x1000] == (0x1003,)
    assert successors[0x1003] == (0x1006,)
    assert successors[0x1006] == (0x100A, 0x100C)
    assert ssa.predecessor_map[0x100A] == (0x1006,)
    assert ssa.predecessor_map[0x100C] == (0x1006, 0x100A)
    assert artifact.summary["block_successor_rewrite_failure_count"] == 0
    assert canonicalize_ir_block_ownership_8616(artifact.blocks).blocks == artifact.blocks


@pytest.mark.parametrize("fault", ["valid", "empty-prefix", "unknown-address", "prefix-overlap", "missing-owner", "branching-owner", "different-exit"])
def test_suffix_chain_requires_exact_prefix_and_all_canonical_edges(fault):
    source = IRBlock(0x100, successor_addrs=(0x200, 0x300))
    retained = (IRInstr("MOV", None, (), addr=0x100),)
    originals = {0x110: IRBlock(0x110, successor_addrs=source.successor_addrs)}
    canonical = {
        0x110: IRBlock(0x110, successor_addrs=(0x120,)),
        0x120: IRBlock(0x120, successor_addrs=source.successor_addrs),
    }
    if fault == "empty-prefix":
        retained = ()
    elif fault == "unknown-address":
        retained = (IRInstr("MOV", None, ()),)
    elif fault == "prefix-overlap":
        retained = (IRInstr("MOV", None, (), addr=0x111),)
    elif fault == "missing-owner":
        del canonical[0x110]
    elif fault == "branching-owner":
        canonical[0x110] = IRBlock(0x110, successor_addrs=(0x120, 0x300))
    elif fault == "different-exit":
        canonical[0x120] = IRBlock(0x120, successor_addrs=(0x400,))
    assert proven_suffix_owner_chain_8616(source, retained, (0x110, 0x120), originals, canonical) is (fault == "valid")
