from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.ir.condition_ir import ConditionFailure, ConditionIR
from angr_platforms.X86_16.ir.condition_lift_capture import (
    isolated_condition_lift_session_8616,
)
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.lift_86_16 import Instruction_ANY
from pytest import MonkeyPatch

from inertia_decompiler.project_loading import _build_project
from scripts.check_sortd_sidecar_free import mz_executable_image

REPO_ROOT = Path(__file__).resolve().parents[2]
SORTDEMO_EXE = REPO_ROOT / "SORTDEMO.EXE"
SLEEP_BLOCK_ADDRS = frozenset(
    {
        0x10F38,
        0x10F41,
        0x10F46,
        0x10F52,
        0x10F55,
        0x10F5A,
        0x10F5D,
        0x10F5F,
        0x10F62,
        0x10F67,
        0x10F6A,
        0x10F6D,
    }
)


def test_default_pipeline_includes_condition_capture_refusals() -> None:
    from scripts.test_pipeline import FOCUSED_PYTEST_TARGETS

    assert "angr_platforms/tests/test_x86_16_condition_lift_capture.py" in FOCUSED_PYTEST_TARGETS


def test_condition_lift_capture_closes_typed_evidence_and_restores_state() -> None:
    condition = ConditionIR(
        "ne",
        "ax",
        0,
        source=("cmp", "jne"),
        src_insn=0x1002,
        block_addr=0x1000,
    )
    original_condition_cache = Instruction_ANY._inertia_module_condition_cache
    original_pending_sources = Instruction_ANY._inertia_pending_condition_sources_by_addr
    original_affine_state = Instruction_ANY._inertia_condition_reg_affine_state_8616
    original_affine_snapshots = Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616
    original_index_state = Instruction_ANY._inertia_condition_index_reg_state_8616
    original_value_state = Instruction_ANY._inertia_condition_reg_value_state_8616

    with isolated_condition_lift_session_8616() as capture:
        Instruction_ANY._inertia_module_condition_cache[0x1000] = [condition]
        capture.record_successful_block(0x1000)
        artifact = capture.complete_artifact(
            frozenset({0x1000}),
            frozenset({0x1000}),
        )

    assert artifact is not None
    assert artifact.stats.complete
    assert artifact.conditions_by_block == ((0x1000, (condition,)),)
    assert Instruction_ANY._inertia_module_condition_cache is original_condition_cache
    assert Instruction_ANY._inertia_pending_condition_sources_by_addr is original_pending_sources
    assert Instruction_ANY._inertia_condition_reg_affine_state_8616 is original_affine_state
    assert Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616 is original_affine_snapshots
    assert Instruction_ANY._inertia_condition_index_reg_state_8616 is original_index_state
    assert Instruction_ANY._inertia_condition_reg_value_state_8616 is original_value_state


def test_condition_lift_capture_refuses_missing_expected_owner() -> None:
    with isolated_condition_lift_session_8616() as capture:
        capture.record_successful_block(0x1000)
        artifact = capture.complete_artifact(
            frozenset({0x1000}),
            frozenset({0x1000}),
        )

    assert artifact is None


@pytest.mark.parametrize("failure_block", [0x1000, 0x1010, 0x2000])
def test_condition_capture_does_not_hide_owned_failure(failure_block: int) -> None:
    with isolated_condition_lift_session_8616() as capture:
        capture.condition_cache[0x1000] = [ConditionIR("ne", "ax", 0, block_addr=0x1000)]
        capture.condition_cache.setdefault(failure_block, []).append(ConditionFailure("unsupported"))
        capture.record_successful_block(0x1000)
        artifact = capture.complete_artifact(frozenset({0x1000, 0x1010}), frozenset({0x1000}))
    if failure_block == 0x2000:
        assert artifact is not None
    else:
        assert artifact is None


def test_exact_relift_preserves_mixed_condition_failure(monkeypatch: MonkeyPatch) -> None:
    from angr_platforms.X86_16.ir import condition_cache_relift as relift

    project = SimpleNamespace(
        arch=object(), loader=SimpleNamespace(memory=SimpleNamespace(load=lambda addr, size: bytes(size))),
    )
    lifts = []

    def lift(data, address, arch):
        lifts.append(address)
        Instruction_ANY._inertia_module_condition_cache[address] = [
            ConditionIR("ne", "ax", 0, block_addr=address), ConditionFailure("unsupported"),
        ]

    monkeypatch.setattr(relift, "_direct_lift_8616", lift)
    for _ in range(2):
        artifact = relift.relift_function_condition_cache_8616(
            project, (relift.ConditionReliftBlock8616(0x3000, 2),), frozenset({0x3000}),
        )
        assert artifact is not None and not artifact.stats.complete
        assert artifact.stats.failure_count == 1
        assert artifact.failures[0].block_addr == 0x3000
        assert artifact.failures[0].reason is relift.ConditionCacheReliftFailureReason8616.CONDITION_RECOVERY_FAILED
    assert lifts == [0x3000, 0x3000]


def test_sortd_ir_build_reuses_complete_frontend_condition_capture(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    from angr_platforms.X86_16.ir import function_condition_artifact as owner

    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))
    project = _build_project(
        isolated_binary,
        force_blob=False,
        base_addr=0x1000,
        entry_point=0x1000,
    )
    function = SimpleNamespace(
        addr=0x10F38,
        block_addrs_set=SLEEP_BLOCK_ADDRS,
        graph=None,
        info={},
    )

    from angr_platforms.X86_16.ir.condition_cache_relift import (
        ConditionCacheReliftArtifact8616,
        ConditionReliftBlock8616,
    )

    original_relift = owner.relift_function_condition_cache_8616

    def checked_relift(
        current_project: object,
        blocks: tuple[ConditionReliftBlock8616, ...],
        expected_condition_blocks: frozenset[int],
    ) -> ConditionCacheReliftArtifact8616 | None:
        """Forbid relifting captured Sleep blocks; preserve nested callee recovery."""
        assert SLEEP_BLOCK_ADDRS.isdisjoint(block.address for block in blocks), (
            "complete frontend capture must avoid exact-byte relift"
        )
        return original_relift(current_project, blocks, expected_condition_blocks)

    monkeypatch.setattr(owner, "relift_function_condition_cache_8616", checked_relift)
    artifact = build_x86_16_ir_function_artifact(project, function)

    assert artifact.condition_evidence is not None
    assert artifact.condition_evidence.complete
    assert artifact.condition_evidence.source.stats.materialized_count == 3
