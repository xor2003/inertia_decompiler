"""Preserve segmented metadata while separating analysis from AST transformations."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from inertia.lowering import segmented_memory_reasoning as memory
from inertia.structuring import decompiler_structuring_stage as stage
from tests.lowering.test_x86_16_segmented_stack_alias import _codegen


def _metadata(surface):
    return {key: value for key, value in vars(surface).items()
            if key.startswith("_inertia_segmented_memory")}


@pytest.mark.parametrize("assignments", [(), (
    memory.SegmentAssignment(memory.SegmentRegister.SS, 0x1000, "literal", "entry", 0.9),
)])
def test_analysis_matches_structuring_full_pass_metadata(assignments):
    project, original = _codegen([])
    project._inertia_decompiler_stage = "structuring:_segmented_memory_reasoning_8616"
    original._inertia_segment_assignments = assignments
    original._inertia_segmented_memory_stats = {"stale": 100}
    analysis = deepcopy(original)
    root = analysis.cfunc.statements
    assert memory.apply_x86_16_segmented_memory_reasoning(original) is False
    assert memory.analyze_x86_16_segmented_memory(analysis) is False
    assert analysis.cfunc.statements is root
    assert _metadata(analysis) == _metadata(original)
    assert _metadata(analysis.project) == _metadata(original.project)
    assert analysis._inertia_segmented_memory_stats["segment_assignments"] == len(assignments)
    assert "stale" not in analysis._inertia_segmented_memory_stats


def test_analysis_never_calls_transformations_outside_structuring(monkeypatch):
    project, codegen = _codegen([])
    project._inertia_decompiler_stage = "postprocess"
    called = []

    def record(*args, **kwargs):
        called.append(True)
        return True

    for name in ("lower_stable_ds_es_linear_global_dereferences_8616",
                 "_apply_ss_stack_slot_recovery_8616", "apply_runtime_segment_lowering_8616"):
        monkeypatch.setattr(memory, name, record)
    root = codegen.cfunc.statements
    assert memory.analyze_x86_16_segmented_memory(codegen) is False
    assert called == []
    assert codegen.cfunc.statements is root
    assert memory.apply_x86_16_segmented_memory_reasoning(codegen) is True
    assert len(called) == 3


def test_missing_function_publishes_nothing():
    codegen = SimpleNamespace()
    assert memory.analyze_x86_16_segmented_memory(codegen) is False
    assert vars(codegen) == {}


def test_analysis_preserves_full_pass_error_and_initial_counters(monkeypatch):
    _project, original = _codegen([])
    analysis = deepcopy(original)

    def fail(_codegen):
        raise ValueError("invalid segment evidence")

    monkeypatch.setattr(memory, "_segment_assignments_or_empty_8616", fail)
    assert memory.apply_x86_16_segmented_memory_reasoning(original) is False
    assert memory.analyze_x86_16_segmented_memory(analysis) is False
    assert _metadata(analysis) == _metadata(original)
    assert analysis._inertia_segmented_memory_error == "invalid segment evidence"
    assert analysis._inertia_segmented_memory_stats == {
        "segment_assignments": 0, "associations_built": 0, "far_pointers_detected": 0,
    }


def test_actual_structuring_spec_is_analysis_only(monkeypatch):
    spec = next(spec for spec in stage._build_decompiler_structuring_passes()
                if spec.name == "_segmented_memory_analysis_8616")
    assert spec.func is memory.analyze_x86_16_segmented_memory
    assert spec.name not in stage._semantic_validation_pass_names_8616()
    assert "_segmented_memory_reasoning_8616" in stage._semantic_validation_pass_names_8616()
    assert spec.needs_project is False
    project, codegen = _codegen([])
    monkeypatch.delenv("INERTIA_VALIDATE_ALL_STRUCTURING_PASSES", raising=False)
    monkeypatch.setattr(stage, "_structuring_pass_validation_skip_reason_8616", lambda *args: None)

    def unexpected(*args, **kwargs):
        pytest.fail("analysis-only pass must not collect a semantic validation summary")

    monkeypatch.setattr(stage, "collect_x86_16_tail_validation_summary", unexpected)
    assert stage._maybe_validate_structuring_pass_8616(project, codegen, spec.name) is None
    assert spec.func(codegen) is False
