"""Regression controls for shared IR/frontend CFG and instruction coverage."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from angr_platforms.X86_16.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from angr_platforms.X86_16.ir.function_ir_registry import publish_function_ir_artifact_8616
from angr_platforms.X86_16.ir.ir_boundary_cfg import (
    closed_ir_boundary_cfg_8616 as _CHECK,
)
from angr_platforms.X86_16.ir.ir_boundary_cfg import (
    prove_ir_boundary_coverage_8616 as _PROVE,
)
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from test_segment_call_binding_regression import _project


def _boundary() -> ExactFunctionRangeBoundary8616:
    return ExactFunctionRangeBoundary8616(
        object(), 0x1000, 0x20, frozenset({0x1000, 0x1010}),
        frozenset({0x1000, 0x1010}), ((0x1000, 0x1010),),
    )


def test_exact_reachable_cfg() -> None:
    """Accept identical entry-reachable block and edge censuses."""
    artifact = IRFunctionArtifact(
        0x1000, (IRBlock(0x1000, successor_addrs=(0x1010,)), IRBlock(0x1010)),
    )
    assert _CHECK(_boundary(), artifact)


@pytest.mark.parametrize("artifact", (
    IRFunctionArtifact(0x1000, ()),
    IRFunctionArtifact(0x1000, (IRBlock(0x1000),)),
    IRFunctionArtifact(0x1000, (IRBlock(0x1000), IRBlock(0x1010))),
    IRFunctionArtifact(0x1000, (
        IRBlock(0x1000, successor_addrs=(0x1010, 0x2000)), IRBlock(0x1010),
    )),
    IRFunctionArtifact(0x1000, (
        IRBlock(0x1000, successor_addrs=(0x1010,)), IRBlock(0x1010), IRBlock(0x1010),
    )),
    IRFunctionArtifact(0x2000, (
        IRBlock(0x1000, successor_addrs=(0x1010,)), IRBlock(0x1010),
    )),
))
def test_incomplete_or_conflicting_cfg_refuses(artifact: IRFunctionArtifact) -> None:
    """Refuse omitted, foreign, duplicated, or escaping control-flow evidence."""
    assert not _CHECK(_boundary(), artifact)


def test_matching_but_disconnected_cfg_refuses() -> None:
    """Set equality alone cannot prove every block reachable from entry."""
    boundary = ExactFunctionRangeBoundary8616(
        object(), 0x1000, 0x20, frozenset({0x1000, 0x1010}), frozenset(), (),
    )
    assert not _CHECK(boundary, IRFunctionArtifact(0x1000, (IRBlock(0x1000), IRBlock(0x1010))))


@pytest.mark.parametrize("defect", (None, "missing", "foreign", "unregistered", "project", "unlocated"))
def test_coverage_requires_registered_complete_instruction_census(defect: str | None) -> None:
    """A matching CFG cannot substitute for exact ownership and instruction coverage."""
    # jmp 0x1010; ret — real decoded blocks, boundary census, and imports.
    code = bytes.fromhex("eb 0e") + bytes(0x0E) + b"\xc3"
    project = _project(code)
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1011)
    assert boundary is not None
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    if defect == "missing":
        artifact = replace(artifact, blocks=(artifact.blocks[0], IRBlock(0x1010)))
    elif defect == "unlocated":
        artifact = replace(artifact, blocks=(artifact.blocks[0], IRBlock(0x1010, instrs=(IRInstr("RET", None, ()),))))
    if defect != "unregistered":
        publish_function_ir_artifact_8616(project, artifact)
    if defect == "foreign":
        artifact = replace(artifact)
    requested_project = SimpleNamespace() if defect == "project" else project
    result = _PROVE(requested_project, boundary, artifact)
    assert result.complete is (defect is None)
    assert result.raw_fact_count == result.normalized_fact_count == 1
    assert result.materialized_count + result.failure_count == 1


def test_retained_coverage_does_not_survive_registry_replacement() -> None:
    """An equal-content replacement cannot borrow the original proof lineage."""
    project = SimpleNamespace()
    artifact = IRFunctionArtifact(0x1000, (IRBlock(
        0x1000, instrs=(IRInstr("RET", None, (), addr=0x1000),),
    ),))
    boundary = ExactFunctionRangeBoundary8616(
        project, 0x1000, 1, frozenset({0x1000}), frozenset({0x1000}), (),
    )
    publish_function_ir_artifact_8616(project, artifact)
    result = _PROVE(project, boundary, artifact)
    assert result.complete
    publish_function_ir_artifact_8616(project, replace(artifact))
    assert not result.complete


def test_instruction_census_permits_lossless_multi_operation_expansion() -> None:
    """One machine instruction can legitimately own several raw IR operations."""
    # push ax; ret — a real push owns many imported IR operations at one head.
    project = _project(bytes.fromhex("50 c3"))
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1002)
    assert boundary is not None
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, artifact)
    result = _PROVE(project, boundary, artifact)
    assert result.complete
    assert sum(
        instruction.addr == 0x1000
        for block in artifact.blocks
        for instruction in block.instrs
    ) > 1
    assert not replace(result, classified_fact_count=True).complete
    assert not replace(result, materialized_count=0).complete
    assert not replace(result, failure_count=1).complete
