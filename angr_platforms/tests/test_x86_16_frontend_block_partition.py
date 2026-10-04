"""Byte-backed regressions for exact decoded block ownership and edges."""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

import pytest
from angr_platforms.X86_16 import frontend_instruction_reachability
from angr_platforms.X86_16.frontend_block_partition import (
    FrontendBlockPartitionFailure8616,
    partition_decoded_blocks_8616,
)
from angr_platforms.X86_16.frontend_capstone_block import DirectCapstoneBlock8616
from angr_platforms.X86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
)
from angr_platforms.X86_16.frontend_instruction_reachability import (
    collect_decoded_block_evidence_8616,
    collect_instruction_reachability_8616,
)
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact

from inertia_decompiler.project_loading import _build_project_from_bytes


@pytest.mark.parametrize("code, split_source, split_target", [
    ("85 c0 74 03 90 eb 01 90 16 1f e8 02 00 c3 90 c3", 0x1007, 0x1008),
    ("85 c0 74 03 90 eb 01 90 39 d8 74 02 eb 00 c3", 0x1007, 0x1008),
    ("85 c0 74 03 90 eb 01 90 90 75 f9 c3", 0x1007, 0x1008),
    ("85 c0 74 04 90 74 02 90 90 c3", 0x1007, 0x1008),
])
def test_shared_suffix_has_one_instruction_owner_and_coherent_ir_edges(
    code: str, split_source: int, split_target: int,
) -> None:
    """A discovered suffix owns its branch or call, not the preceding prefix."""
    program = bytes.fromhex(code)
    project = _build_project_from_bytes(program, base_addr=0x1000, entry_point=0x1000)
    # The first fixture also carries an external callee after the caller RET.
    end = 0x100E if program[8:11] == bytes.fromhex("16 1f e8") else 0x1000 + len(program)
    reachability = collect_instruction_reachability_8616(
        project, entry=0x1000, region_start=0x1000, region_end=end,
    )
    boundary = exact_function_range_boundary_8616(project, 0x1000, end)
    assert boundary is not None and reachability.complete
    partition = reachability.block_partition
    assert partition is not None and partition.complete
    assert partition.raw_fact_count == partition.materialized_count == len(boundary.blocks)
    assert partition.failure_count == 0
    owners = Counter(
        instruction.address
        for block in boundary.blocks
        for instruction in cast(Any, block).capstone.insns
    )
    assert all(count == 1 for count in owners.values()), owners
    assert set(owners) == boundary.reachable_instruction_addrs
    assert (split_source, split_target) in boundary.successor_edges
    assert tuple(edge for edge in boundary.successor_edges if edge[0] == split_source) == (
        (split_source, split_target),
    )
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    assert not artifact.refusals
    assert {(block.addr, target) for block in artifact.blocks for target in block.successor_addrs} == set(
        boundary.successor_edges,
    )
    assert artifact.summary["block_successor_rewrite_failure_count"] == 0
    assert artifact.summary["logical_memory_capture_ownership_discarded_count"] == 0
    assert collect_instruction_reachability_8616(
        project, entry=0x1000, region_start=0x1000, region_end=end,
    ) is reachability


@pytest.mark.parametrize("code, end", [("b8 01 00 c3", 0x1001), ("90 c3", 0x1001)])
def test_return_outside_exact_bounds_cannot_close_reachability(code: str, end: int) -> None:
    """A decoded RET beyond the selected region cannot authorize a boundary."""
    project = _build_project_from_bytes(bytes.fromhex(code), base_addr=0x1000, entry_point=0x1000)
    reachability = collect_instruction_reachability_8616(
        project, entry=0x1000, region_start=0x1000, region_end=end,
    )
    assert not reachability.complete
    assert 0x1000 in reachability.unresolved_block_addrs
    assert reachability.failure_count > 0
    assert exact_function_range_boundary_8616(project, 0x1000, end) is None


def test_mid_instruction_branch_entry_refuses_without_erasing_decoded_blocks() -> None:
    """An alternate decode inside MOV cannot be treated as its aligned suffix."""
    # JNZ into the immediate of MOV AX; normal fallthrough owns the whole MOV.
    project = _build_project_from_bytes(
        bytes.fromhex("75 01 b8 90 90 c3"), base_addr=0x1000, entry_point=0x1000,
    )
    reachability = collect_instruction_reachability_8616(
        project, entry=0x1000, region_start=0x1000, region_end=0x1006,
    )
    assert not reachability.complete
    assert reachability.failure_count > 0
    assert set(reachability.reachable_block_addrs) == {0x1000, 0x1002, 0x1003}
    assert {cast(Any, block).addr for block in reachability.blocks} == {0x1000, 0x1002, 0x1003}
    assert (0x1000, 0x1002) in reachability.successor_edges
    assert (0x1000, 0x1003) in reachability.successor_edges


@pytest.mark.parametrize("fault, expected", [
    ("bytes", FrontendBlockPartitionFailure8616.SUFFIX_BYTES_CONFLICT),
    ("missing-bytes", FrontendBlockPartitionFailure8616.BYTE_EVIDENCE_MISSING),
    ("decode", FrontendBlockPartitionFailure8616.SUFFIX_DECODE_CONFLICT),
    ("extent", FrontendBlockPartitionFailure8616.SUFFIX_EXTENT_CONFLICT),
    ("edges", FrontendBlockPartitionFailure8616.SUCCESSOR_CONFLICT),
])
def test_conflicting_suffix_retains_original_evidence_and_typed_failure(
    fault: str, expected: FrontendBlockPartitionFailure8616,
) -> None:
    """Never trim a tail solely because another block starts at its address."""
    project = _build_project_from_bytes(bytes.fromhex("90 c3"), base_addr=0x1000, entry_point=0x1000)
    source = collect_decoded_block_evidence_8616(project, 0x1000).block
    suffix = collect_decoded_block_evidence_8616(project, 0x1001).block
    assert isinstance(source, DirectCapstoneBlock8616)
    assert isinstance(suffix, DirectCapstoneBlock8616)
    edges: tuple[tuple[int, int], ...] = ()
    source_block: object = source
    if fault == "bytes":
        suffix = replace(suffix, code=b"\x90")
    elif fault == "missing-bytes":
        source_block = SimpleNamespace(addr=source.addr, size=source.size, capstone=source.capstone)
    elif fault == "decode":
        suffix = replace(suffix, instructions=(SimpleNamespace(address=0x1001, size=2),))
    elif fault == "extent":
        suffix = replace(suffix, size=2)
    elif fault == "edges":
        edges = ((0x1000, 0x1001),)
    evidence = partition_decoded_blocks_8616(
        (source_block, suffix), edges, region_start=0x1000, region_end=0x1003,
    )
    assert not evidence.complete
    assert evidence.facts[0].failure is expected
    assert evidence.blocks == (source_block, suffix)
    assert evidence.successor_edges == edges
    assert evidence.raw_fact_count == evidence.normalized_fact_count == evidence.classified_fact_count == 2
    assert evidence.materialized_count + evidence.failure_count == 2


def test_unexpected_decoder_defect_is_not_an_unknown_successor(monkeypatch: pytest.MonkeyPatch) -> None:
    """A programming defect must survive instead of becoming absent evidence."""
    project = _build_project_from_bytes(bytes.fromhex("c3"), base_addr=0x1000, entry_point=0x1000)

    def defect(*_args: object, **_kwargs: object) -> object:
        raise AttributeError("decoder contract defect")

    monkeypatch.setattr(frontend_instruction_reachability, "collect_decoded_block_evidence_8616", defect)
    with pytest.raises(AttributeError, match="decoder contract defect"):
        collect_instruction_reachability_8616(
            project, entry=0x1000, region_start=0x1000, region_end=0x1001,
        )
