"""Source-bound function readiness and invalidation controls.

Real x86-16 binaries bound through the owning registries: unchanged sources
reuse exact artifacts without relift, byte revisions invalidate descendants,
and forged or stale artifacts cannot mint source authority.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from inertia.cli.project_loading import _build_project_from_bytes
from inertia.ir.function_ir_registry import (
    FunctionIRArtifactFailure8616,
    FunctionIRArtifactVerdict8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from inertia.ir.function_readiness_contracts import (
    FunctionSourceBindingProvenance8616,
    FunctionSourceRevision8616,
    observed_function_source_revision_8616,
)


def test_architecture_and_producer_identity_invalidate() -> None:
    from inertia.ir import vex_import

    project, _function = _project(MOV_AX_BX_RET)
    artifact = build_x86_16_ir_function_artifact(project, _function)
    publish_function_ir_artifact_8616(project, artifact)

    old_bits = project.arch.bits
    project.arch.bits = 32 if old_bits != 32 else 16
    try:
        stale = registered_function_ir_artifact_8616(project, BASE)
        assert stale.failure is FunctionIRArtifactFailure8616.SOURCE_REVISION_CHANGED
    finally:
        project.arch.bits = old_bits

    original = vex_import._block_to_ir
    vex_import._block_to_ir = lambda *args, **kwargs: original(*args, **kwargs)
    try:
        stale = registered_function_ir_artifact_8616(project, BASE)
        assert stale.failure is FunctionIRArtifactFailure8616.SOURCE_REVISION_CHANGED
    finally:
        vex_import._block_to_ir = original


def test_foreign_body_with_copied_revision_is_refused() -> None:
    project, _function = _project(MOV_AX_BX_RET)
    foreign_project, foreign_function = _project(MOV_AX_DX_RET)
    foreign = build_x86_16_ir_function_artifact(foreign_project, foreign_function)
    forged = replace(
        foreign,
        source_revision=observed_function_source_revision_8616(project, BASE),
    )

    result = publish_function_ir_artifact_8616(project, forged)

    assert result.verdict is FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE
    assert result.failure is FunctionIRArtifactFailure8616.SOURCE_REVISION_CONFLICT
    ssa = build_x86_16_function_ssa(forged)
    ssa_result = publish_function_ssa_artifact_8616(
        project, ssa, FunctionSSAArtifactStage8616.IR
    )
    assert ssa_result.verdict is FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE
from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    FunctionSSAArtifactStage8616,
    FunctionSSAArtifactVerdict8616,
    function_ssa_artifact_at_address_8616,
    publish_function_ssa_artifact_8616,
    registered_function_ssa_artifact_8616,
)
from inertia.ir.ssa_function import build_x86_16_function_ssa
from inertia.ir.vex_import import build_x86_16_ir_function_artifact

pytestmark = pytest.mark.decompiler

BASE = 0x1000
MOV_AX_BX_RET = bytes.fromhex("89d8c3")  # AX receives entry BX.
MOV_AX_DX_RET = bytes.fromhex("89d0c3")  # AX instead receives entry DX.


def _project(code: bytes):
    project = _build_project_from_bytes(code, base_addr=BASE, entry_point=BASE)
    cfg = project.analyses.CFGFast(normalize=True)
    return project, cfg.functions[BASE]


def _published(code: bytes):
    project, function = _project(code)
    resolution = function_ssa_artifact_at_address_8616(project, BASE)
    assert resolution.verdict is FunctionSSAArtifactVerdict8616.PROVEN
    return project, function, resolution


def test_explicit_cfg_source_owner_outlives_cfg_analysis() -> None:
    """Retained source proof must not depend on an expired weak manager proxy."""
    import gc
    import weakref

    import angr

    project = _build_project_from_bytes(MOV_AX_BX_RET, base_addr=BASE, entry_point=BASE)
    kb = angr.KnowledgeBase(project)
    cfg = project.analyses.CFGFast(normalize=True, kb=kb)
    function = cfg.functions[BASE]
    manager_ref = weakref.ref(kb.functions)
    raw = build_x86_16_ir_function_artifact(project, function)
    assert publish_function_ir_artifact_8616(project, raw).verdict is FunctionIRArtifactVerdict8616.PROVEN
    del function, cfg, kb
    gc.collect()
    assert manager_ref() is not None
    assert registered_function_ir_artifact_8616(project, BASE).artifact is raw


@pytest.mark.parametrize("mutation", ["bytes", "removed_owner", "boundary"])
def test_nondefault_cfg_source_keeps_its_live_function_owner(mutation: str) -> None:
    """An explicit CFG KB owns the source; its removal cannot borrow the default KB."""
    import weakref

    import angr

    from inertia.ir.function_readiness_contracts import function_source_boundary_8616

    project = _build_project_from_bytes(MOV_AX_BX_RET, base_addr=BASE, entry_point=BASE)
    kb = angr.KnowledgeBase(project)
    cfg = project.analyses.CFGFast(normalize=True, kb=kb)
    function = cfg.functions[BASE]
    assert project.kb.functions.function(addr=BASE, create=False) is None
    raw = build_x86_16_ir_function_artifact(project, function)
    published = publish_function_ir_artifact_8616(project, raw)
    assert published.verdict is FunctionIRArtifactVerdict8616.PROVEN
    resolved = function_ssa_artifact_at_address_8616(project, BASE)
    assert resolved.verdict is FunctionSSAArtifactVerdict8616.PROVEN
    ssa = resolved.artifact
    assert ssa is not None
    assert registered_function_ir_artifact_8616(project, BASE).artifact is raw
    assert registered_function_ssa_artifact_8616(project, BASE).artifact is ssa

    if mutation == "bytes":
        project.loader.memory.store(BASE, MOV_AX_DX_RET)
    elif mutation == "boundary":
        # angr's graph property is a disposable cache; mutate its canonical
        # transition graph through the dirty-tracked native boundary API.
        function._clear_transition_graph()
    else:
        # A competing default-KB frame must not rescue the removed producer frame.
        # Copy only a competing frame. Running another CFG analysis here would
        # build new IR and legitimately publish a different source owner.
        competing = function.copy()
        competing._function_manager = weakref.proxy(project.kb.functions)
        project.kb.functions[BASE] = competing
        assert project.kb.functions.function(addr=BASE, create=False) is not None
        del kb.functions[BASE]
        assert kb.functions.function(addr=BASE, create=False) is None
        assert function_source_boundary_8616(project, BASE) is None
    assert registered_function_ir_artifact_8616(project, BASE).verdict is (
        FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE
    )
    assert registered_function_ssa_artifact_8616(project, BASE).verdict is (
        FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE
    )


@pytest.mark.parametrize("lookup_ssa", [False, True])
@pytest.mark.parametrize("source_failure", [
    FunctionIRArtifactFailure8616.SOURCE_REVISION_CHANGED,
    FunctionIRArtifactFailure8616.SOURCE_UNAVAILABLE,
    FunctionIRArtifactFailure8616.SOURCE_REVISION_CONFLICT,
])
def test_direct_source_refusal_revokes_retained_lifecycle(
    lookup_ssa: bool, source_failure: FunctionIRArtifactFailure8616,
) -> None:
    """A checked registry refusal must invalidate every retained lifecycle view."""
    from inertia.ir.function_lifecycle import (
        FunctionStageFailure8616,
        FunctionStageReadiness8616,
        FunctionStageVerdict8616,
    )
    from inertia.ir.function_readiness_contracts import (
        FUNCTION_LIFECYCLE_STAGES_8616,
        FunctionLifecycleStage8616,
    )

    project, _function, resolution = _published(MOV_AX_BX_RET)
    assert resolution.artifact is not None
    ssa = resolution.artifact
    raw = registered_function_ir_artifact_8616(project, BASE).artifact
    assert raw is not None
    state = raw.lifecycle.state
    assert state is ssa.lifecycle.state
    for stage in FUNCTION_LIFECYCLE_STAGES_8616:
        state.observe(FunctionStageReadiness8616(BASE, stage, FunctionStageVerdict8616.CURRENT))
    assert state.maturity is FunctionLifecycleStage8616.REWRITE

    if source_failure is FunctionIRArtifactFailure8616.SOURCE_UNAVAILABLE:
        del project.kb.functions[BASE]
    elif source_failure is FunctionIRArtifactFailure8616.SOURCE_REVISION_CONFLICT:
        if lookup_ssa:
            project._inertia_function_ssa_source_bindings_8616.pop(BASE)
        else:
            project._inertia_function_ir_source_bindings_8616.pop(BASE)
    else:
        project.loader.memory.store(BASE, MOV_AX_DX_RET)
    if lookup_ssa:
        refused = registered_function_ssa_artifact_8616(project, BASE)
        assert refused.failure is {
            FunctionIRArtifactFailure8616.SOURCE_UNAVAILABLE: FunctionSSAArtifactFailure8616.SOURCE_UNAVAILABLE,
            FunctionIRArtifactFailure8616.SOURCE_REVISION_CHANGED: FunctionSSAArtifactFailure8616.SOURCE_REVISION_CHANGED,
            FunctionIRArtifactFailure8616.SOURCE_REVISION_CONFLICT: FunctionSSAArtifactFailure8616.SOURCE_REVISION_CONFLICT,
        }[source_failure]
    else:
        refused = registered_function_ir_artifact_8616(project, BASE)
        assert refused.failure is source_failure

    assert state.maturity is None
    assert state.evaluations[FunctionLifecycleStage8616.IR].failure is {
        FunctionIRArtifactFailure8616.SOURCE_UNAVAILABLE: FunctionStageFailure8616.SOURCE_UNAVAILABLE,
        FunctionIRArtifactFailure8616.SOURCE_REVISION_CHANGED: FunctionStageFailure8616.SOURCE_REVISION_CHANGED,
        FunctionIRArtifactFailure8616.SOURCE_REVISION_CONFLICT: FunctionStageFailure8616.SOURCE_REVISION_CONFLICT,
    }[source_failure]
    assert raw.lifecycle.state is ssa.lifecycle.state is state


def test_source_revision_observed_for_real_boundary() -> None:
    project, function = _project(MOV_AX_BX_RET)
    revision = observed_function_source_revision_8616(project, BASE, boundary=function)
    assert revision is not None
    assert revision.function_addr == BASE
    assert revision.arch_key != ""
    assert revision.blocks and sum(block.size for block in revision.blocks) >= 3


def test_unchanged_source_reuses_exact_artifacts() -> None:
    project, _function, first = _published(MOV_AX_BX_RET)

    replay = function_ssa_artifact_at_address_8616(project, BASE)

    assert replay.artifact is first.artifact
    assert replay.stage is FunctionSSAArtifactStage8616.IR
    assert registered_function_ir_artifact_8616(project, BASE).artifact is not None


def test_built_artifact_carries_builder_attestation() -> None:
    project, function = _project(MOV_AX_BX_RET)
    artifact = build_x86_16_ir_function_artifact(project, function)
    assert not artifact.refusals
    assert isinstance(artifact.source_revision, FunctionSourceRevision8616)
    assert artifact.source_revision.function_addr == BASE
    published = publish_function_ir_artifact_8616(project, artifact)
    assert published.verdict is FunctionIRArtifactVerdict8616.PROVEN
    bindings = project._inertia_function_ir_source_bindings_8616
    assert bindings[BASE].provenance is FunctionSourceBindingProvenance8616.ATTESTED


def test_byte_revision_invalidates_ir_and_ssa_descendants() -> None:
    project, _function, ssa_resolution = _published(MOV_AX_BX_RET)
    assert ssa_resolution.artifact is not None

    project.loader.memory.store(BASE, MOV_AX_DX_RET)

    stale_ir = registered_function_ir_artifact_8616(project, BASE)
    stale_ssa = registered_function_ssa_artifact_8616(project, BASE)
    assert stale_ir.verdict is FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE
    assert stale_ir.failure is FunctionIRArtifactFailure8616.SOURCE_REVISION_CHANGED
    assert stale_ir.artifact is None
    assert stale_ssa.verdict is FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE
    assert stale_ssa.failure is FunctionSSAArtifactFailure8616.SOURCE_REVISION_CHANGED
    assert stale_ssa.artifact is None


def test_stale_representation_cannot_be_republished() -> None:
    project, _function, ssa_resolution = _published(MOV_AX_BX_RET)
    stale_artifact = ssa_resolution.artifact
    assert stale_artifact is not None

    project.loader.memory.store(BASE, MOV_AX_DX_RET)

    republished = publish_function_ssa_artifact_8616(
        project, stale_artifact, FunctionSSAArtifactStage8616.IR
    )
    assert republished.verdict is FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE
    assert republished.failure is FunctionSSAArtifactFailure8616.SOURCE_REVISION_CONFLICT


def test_independent_revision_reanalysis_supersedes() -> None:
    project, _function, _first = _published(MOV_AX_BX_RET)
    project.loader.memory.store(BASE, MOV_AX_DX_RET)

    rebuilt = function_ssa_artifact_at_address_8616(project, BASE)

    assert rebuilt.verdict is FunctionSSAArtifactVerdict8616.PROVEN
    assert rebuilt.artifact is not None
    live = registered_function_ssa_artifact_8616(project, BASE)
    assert live.artifact is rebuilt.artifact


def test_attested_old_generation_cannot_mint_current_source() -> None:
    project, function = _project(MOV_AX_BX_RET)
    artifact = build_x86_16_ir_function_artifact(project, function)
    assert artifact.source_revision is not None

    project.loader.memory.store(BASE, MOV_AX_DX_RET)

    forged = publish_function_ir_artifact_8616(project, artifact)
    assert forged.verdict is FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE
    assert forged.failure is FunctionIRArtifactFailure8616.SOURCE_REVISION_CONFLICT


def test_forged_revision_field_is_not_accepted_as_proof() -> None:
    project, function = _project(MOV_AX_BX_RET)
    artifact = build_x86_16_ir_function_artifact(project, function)
    assert artifact.source_revision is not None
    forged_revision = replace(artifact.source_revision, function_addr=BASE + 1)
    forged = replace(artifact, source_revision=forged_revision)

    result = publish_function_ir_artifact_8616(project, forged)

    assert result.verdict is FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE
    assert result.failure is FunctionIRArtifactFailure8616.SOURCE_REVISION_CONFLICT


def test_artifact_serialization_preserves_source_revision() -> None:
    project, function = _project(MOV_AX_BX_RET)
    artifact = build_x86_16_ir_function_artifact(project, function)
    assert artifact.source_revision is not None

    encoded = artifact.to_dict()
    revision_dict = encoded["source_revision"]

    assert isinstance(revision_dict, dict)
    assert revision_dict["function_addr"] == BASE
    assert revision_dict["blocks"] == [
        block.to_dict() for block in artifact.source_revision.blocks
    ]


def test_direct_publish_binds_observed_generation() -> None:
    project, function = _project(MOV_AX_BX_RET)
    artifact = replace(
        build_x86_16_ir_function_artifact(project, function),
        source_revision=None,
    )

    published = publish_function_ir_artifact_8616(project, artifact)
    assert published.verdict is FunctionIRArtifactVerdict8616.PROVEN
    bindings = project._inertia_function_ir_source_bindings_8616
    assert bindings[BASE].provenance is FunctionSourceBindingProvenance8616.OBSERVED

    project.loader.memory.store(BASE, MOV_AX_DX_RET)
    stale = registered_function_ir_artifact_8616(project, BASE)
    assert stale.failure is FunctionIRArtifactFailure8616.SOURCE_REVISION_CHANGED


def test_runtime_gp_names_do_not_consume_stale_ssa() -> None:
    from types import SimpleNamespace

    from inertia.lowering.gp_register_state import runtime_gp_state_names_8616

    project, _function, _resolution = _published(MOV_AX_BX_RET)
    codegen = SimpleNamespace(
        project=project, cfunc=SimpleNamespace(addr=BASE, statements=[])
    )
    assert "ebx" in runtime_gp_state_names_8616(codegen)

    project.loader.memory.store(BASE, MOV_AX_DX_RET)

    assert "ebx" not in runtime_gp_state_names_8616(codegen)
    readiness = codegen._inertia_gp_state_ssa_readiness_8616
    assert readiness.failure is FunctionSSAArtifactFailure8616.SOURCE_REVISION_CHANGED


def test_native_missing_source_rejects_unbound_artifacts() -> None:
    """Native and original-project scopes cannot admit foreign model evidence."""
    from dataclasses import replace
    from types import SimpleNamespace

    from inertia.ir.function_ssa_registry import (
        FunctionSSAArtifactFailure8616,
        FunctionSSAArtifactStage8616,
        publish_function_ssa_artifact_8616,
    )
    from inertia.ir.ssa_function import build_x86_16_function_ssa

    project, _function = _project(MOV_AX_BX_RET)
    foreign_project, foreign_function = _project(bytes.fromhex("89 d0 c3"))
    foreign = replace(
        build_x86_16_ir_function_artifact(foreign_project, foreign_function),
        source_revision=None,
    )
    del project.kb.functions[BASE]
    assert observed_function_source_revision_8616(project, BASE) is None
    for scope in (project, SimpleNamespace(_inertia_original_project=project)):
        raw = publish_function_ir_artifact_8616(scope, foreign)
        ssa = publish_function_ssa_artifact_8616(
            scope, build_x86_16_function_ssa(foreign), FunctionSSAArtifactStage8616.IR,
        )
        assert raw.failure is FunctionIRArtifactFailure8616.SOURCE_UNAVAILABLE
        assert ssa.failure is FunctionSSAArtifactFailure8616.SOURCE_UNAVAILABLE
        assert raw.artifact is None and ssa.artifact is None


def test_independent_model_publication_remains_available() -> None:
    """An explicit data model still supports registry-only independent proofs."""
    from types import SimpleNamespace

    from inertia.ir import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
    from inertia.ir.function_ssa_registry import (
        FunctionSSAArtifactStage8616,
        publish_function_ssa_artifact_8616,
    )
    from inertia.ir.ssa_function import build_x86_16_function_ssa

    model = SimpleNamespace()
    artifact = IRFunctionArtifact(BASE, (IRBlock(BASE, (
        IRInstr(
            "MOV", IRValue(MemSpace.REG, name="ax", size=2),
            (IRValue(MemSpace.CONST, const=1, size=2),), size=2, addr=BASE,
        ),
    )),))
    raw = publish_function_ir_artifact_8616(model, artifact)
    ssa = publish_function_ssa_artifact_8616(
        model, build_x86_16_function_ssa(artifact), FunctionSSAArtifactStage8616.IR,
    )
    assert raw.artifact is artifact
    assert registered_function_ir_artifact_8616(model, BASE).artifact is artifact
    assert ssa.verdict is FunctionSSAArtifactVerdict8616.PROVEN
    assert registered_function_ssa_artifact_8616(model, BASE).artifact is ssa.artifact


def test_class_implementation_digest_reads_current_module_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Content revisions invalidate a live producer even with unchanged mtime/size."""
    import hashlib
    import json
    import os
    import sys
    from types import ModuleType

    from inertia.ir.function_readiness_contracts import _implementation_digest_8616

    module = ModuleType("readiness_producer_control")
    path = tmp_path / "producer.bin"
    content = b"native implementation\x00" * 4096
    path.write_bytes(content)
    module.__file__ = str(path)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    producer = type("Producer", (), {"__module__": module.__name__})
    identity = (module.__name__, "Producer", [])
    expected = hashlib.sha256(content + json.dumps(identity, ensure_ascii=True).encode("utf-8"))
    before = _implementation_digest_8616(producer)
    assert before == "module:" + expected.hexdigest()
    metadata = path.stat()
    path.write_bytes(b"x" + content[1:])
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    assert path.stat().st_size == metadata.st_size
    assert path.stat().st_mtime_ns == metadata.st_mtime_ns
    assert _implementation_digest_8616(producer) != before


def test_nested_constant_encoding_is_bounded() -> None:
    """Proof revalidation must not repeatedly escape an exponentially growing string."""
    from inertia.ir.function_readiness_contracts import _implementation_constant_8616

    value: object = 'quoted\\value"'
    for _ in range(18):
        value = (value,)
    encoded = _implementation_constant_8616(value)
    assert encoded is not None
    assert len(encoded) <= 4096


def test_implementation_fingerprint_reobserves_mutable_capture() -> None:
    """A bounded representation still observes changed data on the same callable."""
    from inertia.ir.function_readiness_contracts import _implementation_digest_8616

    state = {'mode': (1, 2)}

    def producer() -> tuple[int, int]:
        return state['mode']

    before = _implementation_digest_8616(producer)
    state['mode'] = (1, 3)
    after = _implementation_digest_8616(producer)
    assert before is not None and after is not None and before != after


def test_nested_producer_code_changes_source_identity() -> None:
    """A nested implementation change invalidates identity under stable names."""
    from types import FunctionType

    from inertia.ir import vex_import

    project, _function = _project(MOV_AX_BX_RET)
    original = vex_import._block_to_ir

    def producer(enabled: bool) -> FunctionType:
        """Create same-named producers differing only in a nested constant."""
        namespace: dict[str, object] = {"__name__": "producer_control", "original": original}
        source = (
            "def replacement(*args, **kwargs):\n"
            "    def active():\n"
            f"        return {enabled!r}\n"
            "    if active():\n"
            "        return original(*args, **kwargs)\n"
            "    return None\n"
        )
        exec(source, namespace)
        result = namespace["replacement"]
        assert isinstance(result, FunctionType)
        return result

    try:
        vex_import._block_to_ir = producer(True)
        before = observed_function_source_revision_8616(project, BASE)
        vex_import._block_to_ir = producer(False)
        after = observed_function_source_revision_8616(project, BASE)
        assert before is not None and after is not None
        assert before != after
    finally:
        vex_import._block_to_ir = original


def test_native_standard_x86_source_publication_remains_proven() -> None:
    """The shared source key preserves existing 32-bit native IR publication."""
    import io

    import angr
    from archinfo import ArchX86

    base = 0x400000
    project = angr.Project(
        io.BytesIO(bytes.fromhex("89 d8 c3")),
        main_opts={"backend": "blob", "arch": ArchX86(), "base_addr": base, "entry_point": base},
    )
    cfg = project.analyses.CFGFast(normalize=True)
    artifact = build_x86_16_ir_function_artifact(project, cfg.kb.functions[base])
    result = publish_function_ir_artifact_8616(project, artifact)
    assert not artifact.refusals
    assert result.artifact is artifact
    assert result.failure is None


def test_explicit_native_range_remains_observable_without_function_manager() -> None:
    """An attested exact input range remains native and invalidates after byte changes."""
    from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
    from inertia.ir.function_readiness_contracts import FunctionSourceScope8616

    project = _build_project_from_bytes(MOV_AX_BX_RET, base_addr=BASE, entry_point=BASE)
    boundary = exact_function_range_boundary_8616(project, BASE, BASE + len(MOV_AX_BX_RET))
    assert boundary is not None
    assert observed_function_source_revision_8616(project, BASE) is None
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    assert artifact.source_revision is not None
    assert artifact.source_revision.scope is FunctionSourceScope8616.EXACT_RANGE
    assert artifact.source_revision.range_end == BASE + len(MOV_AX_BX_RET)
    published = publish_function_ir_artifact_8616(project, artifact)
    assert published.verdict is FunctionIRArtifactVerdict8616.PROVEN
    assert registered_function_ir_artifact_8616(project, BASE).artifact is artifact

    project.loader.memory.store(BASE, MOV_AX_DX_RET)
    stale = registered_function_ir_artifact_8616(project, BASE)
    assert stale.artifact is None
    assert stale.failure is FunctionIRArtifactFailure8616.SOURCE_REVISION_CHANGED


def test_copied_explicit_source_scope_cannot_attest_a_foreign_body() -> None:
    """A copied range and revision do not replace the original builder's body record."""
    from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616

    project = _build_project_from_bytes(MOV_AX_BX_RET, base_addr=BASE, entry_point=BASE)
    foreign_project = _build_project_from_bytes(MOV_AX_DX_RET, base_addr=BASE, entry_point=BASE)
    boundary = exact_function_range_boundary_8616(project, BASE, BASE + len(MOV_AX_BX_RET))
    foreign_boundary = exact_function_range_boundary_8616(
        foreign_project, BASE, BASE + len(MOV_AX_DX_RET),
    )
    assert boundary is not None and foreign_boundary is not None
    genuine = build_x86_16_ir_function_artifact(project, boundary)
    foreign = build_x86_16_ir_function_artifact(foreign_project, foreign_boundary)
    forged = replace(foreign, source_revision=genuine.source_revision)
    result = publish_function_ir_artifact_8616(project, forged)
    assert result.verdict is FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE
    assert result.artifact is None


def test_explicit_native_scope_reaches_ssa_and_ir_consumption() -> None:
    """SSA and lifecycle consumers retain the actual explicit source boundary."""
    from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
    from inertia.ir.function_lifecycle import FunctionStageVerdict8616
    from inertia.ir.function_readiness_contracts import FunctionLifecycleStage8616, FunctionSourceScope8616
    from inertia.ir.function_ssa_registry import function_ssa_artifact_for_boundary_8616
    from inertia.pipeline.function_readiness import assert_function_stage_ready_8616

    project = _build_project_from_bytes(MOV_AX_BX_RET, base_addr=BASE, entry_point=BASE)
    boundary = exact_function_range_boundary_8616(project, BASE, BASE + len(MOV_AX_BX_RET))
    assert boundary is not None
    resolution = function_ssa_artifact_for_boundary_8616(project, BASE, boundary)
    assert resolution.artifact is not None
    assert resolution.artifact.source_revision is not None
    assert resolution.artifact.source_revision.scope is FunctionSourceScope8616.EXACT_RANGE
    readiness = assert_function_stage_ready_8616(
        project, BASE, FunctionLifecycleStage8616.IR, layer="test_explicit_scope",
    )
    assert readiness.verdict is FunctionStageVerdict8616.CURRENT


@pytest.mark.parametrize("ssa", [False, True])
def test_function_body_digest_visits_shared_expressions_with_bounded_work(
    monkeypatch: pytest.MonkeyPatch, ssa: bool,
) -> None:
    """Body attestation must not expand every path through a shared expression DAG."""
    from inertia.ir.core import IRBinaryValue, IRBlock, IRInstr, IRValue, MemSpace
    from inertia.ir.function_artifact import IRFunctionArtifact
    from inertia.ir.function_readiness_contracts import function_artifact_body_digest_8616
    from inertia.ir.ssa import SSABinding, SSABlock
    from inertia.ir.ssa_function import SSAFunctionArtifact

    leaf = IRValue(MemSpace.TMP, offset=7, size=2, source_tmp=7)
    node: IRValue | IRBinaryValue = leaf
    for _ in range(16):
        node = IRBinaryValue("Add16", node, node, size=2)
    instruction = IRInstr("R", None, (node,))
    artifact: IRFunctionArtifact | SSAFunctionArtifact
    if ssa:
        artifact = SSAFunctionArtifact(
            0x1000, (SSABlock(0x1000, (instruction,), (SSABinding(leaf, 1, 0),)),),
        )
    else:
        artifact = IRFunctionArtifact(0x1000, (IRBlock(0x1000, (instruction,)),))
    original = IRBinaryValue.to_dict
    calls = 0

    def counted(value: IRBinaryValue) -> dict[str, object]:
        nonlocal calls
        calls += 1
        assert calls <= 128, "body digest expanded shared expression paths"
        return original(value)

    monkeypatch.setattr(IRBinaryValue, "to_dict", counted)
    assert function_artifact_body_digest_8616(artifact) is not None


@pytest.mark.parametrize("ssa", [False, True])
def test_non_block_body_payload_keeps_every_owned_artifact_field(ssa: bool) -> None:
    """Diagnostic and body projections must share all non-block dataclass fields."""
    from dataclasses import fields

    from inertia.ir.function_artifact import IRFunctionArtifact
    from inertia.ir.ssa_function import SSAFunctionArtifact

    artifact = SSAFunctionArtifact(0x1000, ()) if ssa else IRFunctionArtifact(0x1000)
    metadata = artifact.non_block_payload_8616()
    assert set(metadata) | {"blocks"} == {field.name for field in fields(artifact)}
    assert artifact.to_dict() == {**metadata, "blocks": []}


@pytest.mark.parametrize("changed", ["target", "version", "instruction", "address", "refusal", "group"])
def test_body_digest_retains_ssa_definition_and_group_coordinates(changed: str) -> None:
    """Finite body graphs must keep SSA target provenance, order and block metadata."""
    from inertia.ir.core import IRInstr, IRValue, MemSpace
    from inertia.ir.function_readiness_contracts import function_artifact_body_digest_8616
    from inertia.ir.ssa import SSABinding, SSABlock
    from inertia.ir.ssa_function import SSAFunctionArtifact

    target = IRValue(MemSpace.TMP, offset=7, size=2, source_tmp=7)
    binding = SSABinding(target, 1, 0)
    instruction = IRInstr("R", None, (target,))
    block = SSABlock(0x1000, (instruction,), (binding,))
    baseline = SSAFunctionArtifact(0x1000, (block,))
    if changed == "target":
        block = replace(block, bindings=(replace(binding, target=replace(target, source_tmp=8)),))
    elif changed == "version":
        block = replace(block, bindings=(replace(binding, version=2),))
    elif changed == "instruction":
        block = replace(block, bindings=(replace(binding, instr_index=1),))
    elif changed == "address":
        block = replace(block, addr=0x1001)
    elif changed == "refusal":
        block = replace(block, refusals=("unknown",))
    else:
        block = replace(block, instrs=())
    blocks = (block, SSABlock(0x1001, (instruction,), ())) if changed == "group" else (block,)
    original = function_artifact_body_digest_8616(baseline)
    assert original is not None
    assert function_artifact_body_digest_8616(replace(baseline, blocks=blocks)) != original
