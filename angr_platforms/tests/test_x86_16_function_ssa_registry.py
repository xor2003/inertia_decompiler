from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.ir import IRFunctionArtifact, vex_import
from angr_platforms.X86_16.ir.function_ir_registry import (
    FunctionIRArtifactFailure8616,
    FunctionIRArtifactVerdict8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from angr_platforms.X86_16.ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    FunctionSSAArtifactStage8616,
    FunctionSSAArtifactVerdict8616,
    publish_function_ssa_artifact_8616,
    registered_function_ssa_artifact_8616,
)
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.ir.vex_import import apply_x86_16_vex_ir_artifact
from angr_platforms.X86_16.semantics import call_stack_effect_pipeline
from angr_platforms.X86_16.semantics.call_output_contracts import CallOutputStats8616
from angr_platforms.X86_16.semantics.call_outputs import CallOutputArtifact8616
from angr_platforms.X86_16.semantics.call_stack_effect_contracts import (
    CallStackEffectStats8616,
)
from angr_platforms.X86_16.semantics.call_stack_effect_pipeline import (
    apply_x86_16_call_stack_effects_8616,
    semantic_function_ssa_artifact_at_address_8616,
)
from angr_platforms.X86_16.semantics.call_stack_effects import (
    CallStackEffectArtifact8616,
)


def _ssa(function_addr: int, marker: str) -> SSAFunctionArtifact:
    return SSAFunctionArtifact(function_addr, (), summary={"marker": marker})


class _Functions:
    def __init__(self, *addresses: int) -> None:
        self._functions = {
            address: SimpleNamespace(addr=address, info=None) for address in addresses
        }

    def function(self, *, addr: int, create: bool = False) -> object | None:
        assert create is False
        return self._functions.get(addr)


def _project(*addresses: int) -> SimpleNamespace:
    return SimpleNamespace(kb=SimpleNamespace(functions=_Functions(*addresses)))


def test_raw_ir_registry_reuses_one_exact_artifact() -> None:
    project = _project()
    artifact = IRFunctionArtifact(0x1000, (), summary={"marker": "raw"})

    published = publish_function_ir_artifact_8616(project, artifact)
    replay = registered_function_ir_artifact_8616(project, 0x1000)

    assert published.verdict is FunctionIRArtifactVerdict8616.PROVEN
    assert replay.artifact is artifact
    assert replay.failure is None


def test_raw_ir_registry_refuses_conflicts_without_replacement() -> None:
    project = _project()
    accepted = IRFunctionArtifact(0x1000, (), summary={"marker": "accepted"})
    conflicting = IRFunctionArtifact(0x1000, (), summary={"marker": "conflict"})
    publish_function_ir_artifact_8616(project, accepted)

    result = publish_function_ir_artifact_8616(project, conflicting)

    assert result.verdict is FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE
    assert result.failure is FunctionIRArtifactFailure8616.ARTIFACT_CONFLICT
    assert registered_function_ir_artifact_8616(project, 0x1000).artifact is accepted


def test_raw_ir_lookup_refuses_without_creating_registry() -> None:
    project = _project()
    before = dict(vars(project))

    result = registered_function_ir_artifact_8616(project, 0x1000)

    assert result.verdict is FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE
    assert result.failure is FunctionIRArtifactFailure8616.NOT_REGISTERED
    assert result.artifact is None
    assert vars(project) == before


def test_raw_ir_lookup_miss_preserves_existing_registry() -> None:
    project = _project()
    artifact = IRFunctionArtifact(0x1000, (), summary={"marker": "raw"})
    publish_function_ir_artifact_8616(project, artifact)
    registry = project._inertia_function_ir_artifacts_8616
    before = dict(registry)

    result = registered_function_ir_artifact_8616(project, 0x2000)

    assert result.verdict is FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE
    assert result.failure is FunctionIRArtifactFailure8616.NOT_REGISTERED
    assert project._inertia_function_ir_artifacts_8616 is registry
    assert registry == before
    assert registry[0x1000] is artifact


def test_raw_ir_lookup_rejects_malformed_registry() -> None:
    project = _project()
    malformed: object = [0x1000]
    project._inertia_function_ir_artifacts_8616 = malformed

    with pytest.raises(TypeError, match="must be a dict"):
        registered_function_ir_artifact_8616(project, 0x1000)
    with pytest.raises(TypeError, match="must be a dict"):
        publish_function_ir_artifact_8616(project, IRFunctionArtifact(0x2000, ()))

    assert project._inertia_function_ir_artifacts_8616 is malformed


def test_registry_upgrades_ir_to_semantics_without_downgrade() -> None:
    project = _project()
    raw = _ssa(0x1000, "raw")
    semantic = _ssa(0x1000, "semantic")

    raw_result = publish_function_ssa_artifact_8616(
        project,
        raw,
        FunctionSSAArtifactStage8616.IR,
    )
    semantic_result = publish_function_ssa_artifact_8616(
        project,
        semantic,
        FunctionSSAArtifactStage8616.SEMANTIC,
    )
    downgrade_result = publish_function_ssa_artifact_8616(
        project,
        raw,
        FunctionSSAArtifactStage8616.IR,
    )

    assert raw_result.artifact is raw
    assert semantic_result.artifact is semantic
    assert semantic_result.stage is FunctionSSAArtifactStage8616.SEMANTIC
    assert downgrade_result.artifact is semantic
    assert registered_function_ssa_artifact_8616(project, 0x1000).artifact is semantic


def test_registry_refuses_divergent_semantics_without_replacement() -> None:
    project = _project()
    accepted = _ssa(0x1000, "accepted")
    conflicting = _ssa(0x1000, "conflicting")
    publish_function_ssa_artifact_8616(
        project,
        accepted,
        FunctionSSAArtifactStage8616.SEMANTIC,
    )

    result = publish_function_ssa_artifact_8616(
        project,
        conflicting,
        FunctionSSAArtifactStage8616.SEMANTIC,
    )

    assert result.verdict is FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE
    assert result.failure is FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT
    assert registered_function_ssa_artifact_8616(project, 0x1000).artifact is accepted


def test_vex_apply_reuses_matching_raw_ir_and_ir_stage_ssa(monkeypatch) -> None:
    function_addr = 0x1000
    project = _project(function_addr)
    raw_ir = IRFunctionArtifact(function_addr, ())
    raw_ssa = _ssa(function_addr, "raw")
    publish_function_ir_artifact_8616(project, raw_ir)
    publish_function_ssa_artifact_8616(
        project,
        raw_ssa,
        FunctionSSAArtifactStage8616.IR,
    )

    def _unexpected_build(_project: object, _function: object) -> IRFunctionArtifact:
        raise AssertionError("matching registered raw IR must be reused")

    monkeypatch.setattr(
        vex_import,
        "build_x86_16_ir_function_artifact",
        _unexpected_build,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=function_addr))

    assert apply_x86_16_vex_ir_artifact(project, codegen) is False
    assert codegen._inertia_raw_vex_ir_artifact_8616 is raw_ir
    assert codegen._inertia_raw_vex_ir_function_ssa_8616 is raw_ssa


def test_vex_apply_does_not_downgrade_semantic_ssa(monkeypatch) -> None:
    function_addr = 0x1000
    project = _project(function_addr)
    raw_ir = IRFunctionArtifact(function_addr, ())
    semantic_ssa = _ssa(function_addr, "semantic")
    rebuilt_raw_ssa = _ssa(function_addr, "rebuilt-raw")
    publish_function_ir_artifact_8616(project, raw_ir)
    publish_function_ssa_artifact_8616(
        project,
        semantic_ssa,
        FunctionSSAArtifactStage8616.SEMANTIC,
    )

    def _unexpected_build(_project: object, _function: object) -> IRFunctionArtifact:
        raise AssertionError("matching registered raw IR must be reused")

    monkeypatch.setattr(
        vex_import,
        "build_x86_16_ir_function_artifact",
        _unexpected_build,
    )
    monkeypatch.setattr(
        vex_import,
        "build_x86_16_function_ssa",
        lambda _artifact: rebuilt_raw_ssa,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=function_addr))

    assert apply_x86_16_vex_ir_artifact(project, codegen) is False
    assert codegen._inertia_raw_vex_ir_function_ssa_8616 is rebuilt_raw_ssa
    registered = registered_function_ssa_artifact_8616(project, function_addr)
    assert registered.artifact is semantic_ssa
    assert registered.stage is FunctionSSAArtifactStage8616.SEMANTIC


def test_semantic_lookup_caches_distinct_exact_functions(monkeypatch) -> None:
    project = _project(0x1000, 0x2000)
    publish_function_ssa_artifact_8616(
        project,
        _ssa(0x1000, "raw"),
        FunctionSSAArtifactStage8616.IR,
    )
    built: list[int] = []

    def _build(
        _project: object,
        function: object,
        *,
        ir_artifact: IRFunctionArtifact | None = None,
    ) -> tuple[object, object, SSAFunctionArtifact]:
        assert isinstance(ir_artifact, IRFunctionArtifact)
        function_addr = function.addr
        assert ir_artifact.function_addr == function_addr
        built.append(function_addr)
        effects = CallStackEffectArtifact8616(ir_artifact, (), CallStackEffectStats8616())
        outputs = CallOutputArtifact8616(ir_artifact, (), CallOutputStats8616())
        return effects, outputs, _ssa(function_addr, "semantic")

    monkeypatch.setattr(
        call_stack_effect_pipeline,
        "build_semantic_function_ssa_8616",
        _build,
    )

    first = semantic_function_ssa_artifact_at_address_8616(project, 0x1000)
    replay = semantic_function_ssa_artifact_at_address_8616(project, 0x1000)
    second = semantic_function_ssa_artifact_at_address_8616(project, 0x2000)

    assert built == [0x1000, 0x2000]
    assert first.artifact is replay.artifact
    assert first.stage is second.stage is FunctionSSAArtifactStage8616.SEMANTIC
    assert first.artifact is not second.artifact
    assert semantic_function_ssa_artifact_at_address_8616(
        project,
        0x3000,
    ).failure is FunctionSSAArtifactFailure8616.FUNCTION_NOT_FOUND


def test_main_semantics_path_publishes_its_exact_ssa(monkeypatch) -> None:
    function_addr = 0x1000
    project = _project(function_addr)
    raw_ir = IRFunctionArtifact(function_addr, ())
    semantic_ir = IRFunctionArtifact(function_addr, (), summary={"stage": "semantic"})
    semantic_ssa = _ssa(function_addr, "semantic")
    effects = CallStackEffectArtifact8616(raw_ir, (), CallStackEffectStats8616())
    outputs = CallOutputArtifact8616(semantic_ir, (), CallOutputStats8616())
    build_count = 0

    def _build(
        _project: object,
        function: object,
        *,
        ir_artifact: IRFunctionArtifact | None = None,
    ) -> tuple[object, object, SSAFunctionArtifact]:
        nonlocal build_count
        build_count += 1
        assert function.addr == function_addr
        assert ir_artifact is raw_ir
        return effects, outputs, semantic_ssa

    monkeypatch.setattr(
        call_stack_effect_pipeline,
        "build_semantic_function_ssa_8616",
        _build,
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=function_addr),
        _inertia_vex_ir_artifact=raw_ir,
        _inertia_raw_vex_ir_artifact_8616=raw_ir,
    )

    assert apply_x86_16_call_stack_effects_8616(project, codegen) is False
    assert apply_x86_16_call_stack_effects_8616(project, codegen) is False

    registered = registered_function_ssa_artifact_8616(project, function_addr)
    assert registered.artifact is semantic_ssa
    assert registered.stage is FunctionSSAArtifactStage8616.SEMANTIC
    assert codegen._inertia_vex_ir_function_ssa is semantic_ssa
    assert codegen._inertia_vex_ir_artifact is semantic_ir
    assert (
        codegen._inertia_vex_ir_function_ssa_stage_8616
        is FunctionSSAArtifactStage8616.SEMANTIC
    )
    assert build_count == 1


def test_main_semantics_refused_source_stops_before_build_or_publication(monkeypatch) -> None:
    """Retained import refusals fail early with their exact source diagnostics."""
    from angr_platforms.X86_16.ir import IRRefusal
    from angr_platforms.X86_16.pipeline.errors import PipelineHardError

    function_addr = 0x1000
    project = _project(function_addr)
    refusal = IRRefusal("unknown_effect", "instruction effects are incomplete", 0x1004)
    raw_ir = IRFunctionArtifact(function_addr, (), refusals=(refusal,))
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=function_addr),
        _inertia_vex_ir_artifact=raw_ir,
        _inertia_raw_vex_ir_artifact_8616=raw_ir,
    )

    def forbidden(*args, **kwargs):
        pytest.fail("refused source reached expensive build or artifact publication")

    for name in (
        "build_semantic_function_ssa_8616",
        "publish_function_ir_artifact_8616",
        "publish_function_ssa_artifact_8616",
        "publish_call_semantic_projection_8616",
    ):
        monkeypatch.setattr(call_stack_effect_pipeline, name, forbidden)
    before_project = dict(vars(project))
    before_codegen = dict(vars(codegen))
    with pytest.raises(PipelineHardError) as caught:
        apply_x86_16_call_stack_effects_8616(project, codegen)
    assert caught.value.details == {
        "function_addr": function_addr,
        "failure": FunctionIRArtifactFailure8616.ARTIFACT_REFUSED.value,
        "refusals": [refusal.to_dict()],
    }
    assert vars(project) == before_project
    assert vars(codegen) == before_codegen
