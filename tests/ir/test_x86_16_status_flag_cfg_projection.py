"""Tests for projecting status-flag evidence across rebased exact slices."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import inertia.ir.status_flag_cfg_projection as status_flag_cfg_projection
from inertia.cli.project_loading import _build_project_from_bytes
from inertia.ir import vex_import
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRRefusal
from inertia.ir.status_flag_binary_cfg import (
    BinaryStatusFlagReadSummary8616,
)
from inertia.semantics.status_flag_contracts import STATUS_FLAGS_8616, StatusFlag8616


@pytest.mark.parametrize("incomplete", [False, True])
def test_flag_projection_uses_raw_cfg_without_recursive_proof(monkeypatch, incomplete):
    """Optional flag optimization must not start whole-function call proofs."""
    refusal = IRRefusal("unmodeled_control", "unknown successor", 0x1000)
    artifact = IRFunctionArtifact(
        0x1000,
        blocks=(IRBlock(0x1000),),
        refusals=(refusal,) if incomplete else (),
    )
    seen = []

    def raw(project, function):
        seen.append((project, function))
        return SimpleNamespace(artifact=artifact)

    def forbidden(*args, **kwargs):
        pytest.fail("flag projection started universal semantic proof")

    monkeypatch.setattr(vex_import, "raw_x86_16_function_bundle_8616", raw)
    # Also intercept an already imported legacy producer before the fix.
    monkeypatch.setattr(status_flag_cfg_projection, "build_x86_16_ir_function_artifact", forbidden, raising=False)
    monkeypatch.setattr(status_flag_cfg_projection, "raw_x86_16_function_bundle_8616", raw, raising=False)
    instruction = SimpleNamespace(address=0x1000, mnemonic="cmp", operands=())
    project = SimpleNamespace(factory=SimpleNamespace(block=lambda *a, **kw: SimpleNamespace(
        capstone=SimpleNamespace(insns=(SimpleNamespace(insn=instruction),)),
    )))
    function = SimpleNamespace(addr=0x1000)
    resolver = status_flag_cfg_projection._StatusFlagFunctionSummaryResolver8616(project)
    projection = resolver.projection_for(function, exit_live=StatusFlag8616.NONE)

    assert seen == [(project, function)]
    assert projection.blocks[0].successors_complete is not incomplete
    decision = projection.liveness.decisions[0]
    assert decision.dead_writes == (StatusFlag8616.NONE if incomplete else STATUS_FLAGS_8616)


def _project(start: int, end: int) -> SimpleNamespace:
    return SimpleNamespace(
        loader=SimpleNamespace(
            main_object=SimpleNamespace(min_addr=start, max_addr=end - 1),
        ),
    )


def test_rebased_slice_summarizes_out_of_slice_callee_in_original_image(
    monkeypatch,
) -> None:
    original = _project(0x10000, 0x20000)
    rebased = _project(0x1000, 0x1100)
    rebased._inertia_original_project = original
    rebased._inertia_original_linear_delta = 0xF000
    seen: list[tuple[object, int]] = []

    def summarize(project: object, *, entry_address: int, **_kwargs):
        seen.append((project, entry_address))
        return BinaryStatusFlagReadSummary8616(
            StatusFlag8616.NONE,
            1,
            1,
            1,
            1,
            0,
            overwrites=StatusFlag8616.CARRY,
        )

    monkeypatch.setattr(
        status_flag_cfg_projection,
        "summarize_binary_status_flag_entry_reads_8616",
        summarize,
    )

    resolver = status_flag_cfg_projection._StatusFlagFunctionSummaryResolver8616(rebased)
    effect = resolver.effect_for_address(0x900)

    assert effect is not None
    assert effect.reads is StatusFlag8616.NONE
    assert effect.overwrites is StatusFlag8616.CARRY
    assert seen == [(original, 0xF900)]


def test_rebased_slice_keeps_in_slice_callee_in_slice(monkeypatch) -> None:
    original = _project(0x10000, 0x20000)
    rebased = _project(0x1000, 0x1100)
    rebased._inertia_original_project = original
    rebased._inertia_original_linear_delta = 0xF000
    seen: list[tuple[object, int]] = []

    def summarize(project: object, *, entry_address: int, **_kwargs):
        seen.append((project, entry_address))
        return BinaryStatusFlagReadSummary8616(
            StatusFlag8616.NONE,
            1,
            1,
            1,
            1,
            0,
        )

    monkeypatch.setattr(
        status_flag_cfg_projection,
        "summarize_binary_status_flag_entry_reads_8616",
        summarize,
    )

    resolver = status_flag_cfg_projection._StatusFlagFunctionSummaryResolver8616(rebased)
    assert resolver.effect_for_address(0x1004) is not None
    assert seen == [(rebased, 0x1004)]


@pytest.mark.parametrize(
    "caller,callee,reads,overwrites",
    [
        ("e80d009c58c3", "83f800c3", StatusFlag8616.NONE, STATUS_FLAGS_8616),
        ("9ce80c0058c3", "83f800c3", STATUS_FLAGS_8616, STATUS_FLAGS_8616),
        ("e80d009c58c3", "90c3", STATUS_FLAGS_8616, StatusFlag8616.NONE),
    ],
    ids=("save-after-overwrite", "save-before-overwrite", "preserving-callee"),
)
def test_binary_nested_call_flag_summary_preserves_read_order(caller, callee, reads, overwrites):
    """Actual CALL/PUSHF bytes must distinguish caller FLAGS from callee FLAGS."""
    code = bytes.fromhex(caller) + b"\x90" * 10 + bytes.fromhex(callee)
    project = _build_project_from_bytes(code, base_addr=0x1000, entry_point=0x1000)
    resolver = status_flag_cfg_projection._StatusFlagFunctionSummaryResolver8616(project)
    effect = resolver.effect_for_address(0x1000)
    assert effect is not None
    assert effect.reads == reads
    assert effect.overwrites == overwrites
