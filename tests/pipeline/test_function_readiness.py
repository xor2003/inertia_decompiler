"""Typed six-stage readiness governance and dependent invalidation controls."""

from __future__ import annotations

from contextvars import copy_context
from dataclasses import dataclass
from itertools import count
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeFunction, SimTypeShort

from inertia.cli.project_loading import _build_project_from_bytes
from inertia.ir.function_lifecycle import (
    FunctionStageEvidence8616,
    FunctionStageFailure8616,
    FunctionStageReadiness8616,
    FunctionStageVerdict8616,
)
from inertia.ir.function_readiness_contracts import (
    FUNCTION_LIFECYCLE_STAGES_8616,
    FunctionLifecycleStage8616,
)
from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactVerdict8616,
    function_ssa_artifact_at_address_8616,
)
from inertia.pipeline import function_readiness as readiness_owner
from inertia.pipeline.contracts import (
    CORE_DECOMPILER_PIPELINE_ORDER_8616,
    SemanticLaneState,
    assert_pipeline_contracts_8616,
)
from inertia.pipeline.errors import PipelineHardError
from inertia.pipeline.function_readiness import (
    assert_function_stage_ready_8616,
    drop_function_stage_evidence_8616,
    function_stage_evidence_map_8616,
    function_stage_readiness_8616,
    handoff_function_ast_to_rewrite_8616,
    record_function_ast_stage_evidence_8616,
    record_function_stage_evidence_8616,
)

pytestmark = pytest.mark.decompiler

BASE = 0x1000
MOV_AX_BX_RET = bytes.fromhex("89d8c3")
MOV_AX_DX_RET = bytes.fromhex("89d0c3")


def _project(code: bytes) -> tuple[object, object]:
    project = _build_project_from_bytes(code, base_addr=BASE, entry_point=BASE)
    cfg = project.analyses.CFGFast(normalize=True)
    return project, cfg.functions[BASE]


def _codegen(project: object) -> SimpleNamespace:
    return SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(addr=BASE, statements=[]),
    )


def test_public_order_derives_from_canonical_stage_owner() -> None:
    """Public order derives from canonical stage owner."""
    assert tuple(
        stage.value for stage in (
            FunctionLifecycleStage8616.IR,
            FunctionLifecycleStage8616.ALIAS,
            FunctionLifecycleStage8616.WIDENING,
            FunctionLifecycleStage8616.TYPES,
            FunctionLifecycleStage8616.STRUCTURING,
            FunctionLifecycleStage8616.REWRITE,
        )
    ) == CORE_DECOMPILER_PIPELINE_ORDER_8616


def test_untracked_native_stage_is_reported_but_not_admitted() -> None:
    """Diagnostics keep an untracked verdict; native consumption refuses it."""
    project, _function = _project(MOV_AX_BX_RET)
    readiness = function_stage_readiness_8616(
        project, BASE, FunctionLifecycleStage8616.TYPES
    )
    assert readiness.verdict is FunctionStageVerdict8616.UNTRACKED
    assert readiness.failure is None
    assert function_ssa_artifact_at_address_8616(project, BASE).artifact is not None
    with pytest.raises(PipelineHardError) as caught:
        assert_function_stage_ready_8616(
            project, BASE, FunctionLifecycleStage8616.REWRITE, layer="test"
        )
    assert caught.value.details["failure"] == "stage_not_produced"
    assert caught.value.details["blocking_stage"] == "Alias"


def test_recorded_evidence_is_current_under_unchanged_source() -> None:
    """Recorded evidence is current under unchanged source."""
    project, _function = _project(MOV_AX_BX_RET)
    record_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.IR, producer="test"
    )
    record_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.ALIAS, producer="test"
    )

    readiness = function_stage_readiness_8616(
        project, BASE, FunctionLifecycleStage8616.REWRITE
    )

    assert readiness.verdict is FunctionStageVerdict8616.UNTRACKED
    evidence = function_stage_evidence_map_8616(project, BASE)
    assert evidence[FunctionLifecycleStage8616.ALIAS].producer == "test"
    assert evidence[FunctionLifecycleStage8616.ALIAS].source_revision is not None


def test_byte_revision_stales_recorded_dependents() -> None:
    """Byte revision stales recorded dependents."""
    project, _function = _project(MOV_AX_BX_RET)
    record_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.ALIAS, producer="test"
    )

    project.loader.memory.store(BASE, MOV_AX_DX_RET)

    readiness = function_stage_readiness_8616(
        project, BASE, FunctionLifecycleStage8616.STRUCTURING
    )
    assert readiness.verdict is FunctionStageVerdict8616.STALE
    assert readiness.blocking_stage is FunctionLifecycleStage8616.ALIAS
    assert readiness.failure is FunctionStageFailure8616.SOURCE_REVISION_CHANGED
    with pytest.raises(PipelineHardError) as caught:
        assert_function_stage_ready_8616(
            project, BASE, FunctionLifecycleStage8616.REWRITE, layer="test"
        )
    assert caught.value.details["failure"] == "source_revision_changed"


def test_upstream_evidence_change_stales_dependent_with_same_bytes() -> None:
    """Upstream evidence change stales dependent with same bytes."""
    project, _function = _project(MOV_AX_BX_RET)
    first_output = SimpleNamespace(tag="first")
    second_output = SimpleNamespace(tag="second")
    record_function_stage_evidence_8616(
        project,
        BASE,
        FunctionLifecycleStage8616.IR,
        producer="ir_builder",
        outputs=(first_output,),
    )
    record_function_stage_evidence_8616(
        project,
        BASE,
        FunctionLifecycleStage8616.TYPES,
        producer="test",
        upstream=((FunctionLifecycleStage8616.IR, first_output),),
    )

    record_function_stage_evidence_8616(
        project,
        BASE,
        FunctionLifecycleStage8616.IR,
        producer="ir_builder",
        outputs=(second_output,),
    )

    readiness = function_stage_readiness_8616(
        project, BASE, FunctionLifecycleStage8616.TYPES
    )
    assert readiness.verdict is FunctionStageVerdict8616.STALE
    assert readiness.blocking_stage is FunctionLifecycleStage8616.TYPES
    assert readiness.failure is FunctionStageFailure8616.UPSTREAM_EVIDENCE_CHANGED


def test_dropped_upstream_evidence_stales_dependent() -> None:
    """Dropped upstream evidence stales dependent."""
    project, _function = _project(MOV_AX_BX_RET)
    record_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.ALIAS, producer="test"
    )
    record_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.TYPES, producer="test"
    )

    drop_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.ALIAS
    )

    readiness = function_stage_readiness_8616(
        project, BASE, FunctionLifecycleStage8616.TYPES
    )
    assert readiness.verdict is FunctionStageVerdict8616.STALE
    assert readiness.failure is FunctionStageFailure8616.UPSTREAM_EVIDENCE_CHANGED


def test_stale_ssa_registry_blocks_stage_readiness() -> None:
    """Stale ssa registry blocks stage readiness."""
    project, _function = _project(MOV_AX_BX_RET)
    resolution = function_ssa_artifact_at_address_8616(project, BASE)
    assert resolution.verdict is FunctionSSAArtifactVerdict8616.PROVEN

    project.loader.memory.store(BASE, MOV_AX_DX_RET)

    readiness = function_stage_readiness_8616(
        project, BASE, FunctionLifecycleStage8616.REWRITE
    )
    assert readiness.verdict is FunctionStageVerdict8616.STALE
    assert readiness.blocking_stage is FunctionLifecycleStage8616.IR


def test_contract_gate_refuses_stale_evidence_at_consuming_boundary() -> None:
    """Contract gate refuses stale evidence at consuming boundary."""
    project, _function = _project(MOV_AX_BX_RET)
    codegen = _codegen(project)
    codegen._inertia_stack_lane = SemanticLaneState(name="stack")
    record_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.TYPES, producer="test"
    )

    project.loader.memory.store(BASE, MOV_AX_DX_RET)

    with pytest.raises(PipelineHardError):
        assert_pipeline_contracts_8616(codegen)


def _native_ast_fixture(project: object) -> tuple[SimpleNamespace, structured_c.CConstant]:
    """Build actual boundary nodes for governance tests, without claiming equivalence."""
    indices = count()
    codegen = SimpleNamespace(project=project, next_node_idx=indices.__next__, next_ident=lambda name: name)
    manager = SimpleNamespace(types=SimpleNamespace(iter_own=lambda: ()), get_variable_type=lambda variable: None)
    value_type = SimTypeShort(signed=False).with_arch(project.arch)
    constant = structured_c.CConstant(3, value_type, codegen=codegen)
    codegen.cfunc = structured_c.CFunction(
        BASE, "governance_fixture", SimTypeFunction([], value_type).with_arch(project.arch),
        [], structured_c.CReturn(constant, codegen=codegen), {}, manager, codegen=codegen,
    )
    return codegen, constant


def _record_native_prefix(project: object) -> None:
    """Bind the real SSA body and the modeled prefix stage evidence."""
    assert function_ssa_artifact_at_address_8616(project, BASE).artifact is not None
    for stage in FUNCTION_LIFECYCLE_STAGES_8616[:4]:
        record_function_stage_evidence_8616(
            project, BASE, stage, producer="test_governance_prefix", outputs=(stage,),
        )


def _publish_native_ast_pair(project: object, codegen: object) -> None:
    """Publish actual AST versions around the explicit consuming handoff."""
    record_function_ast_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.STRUCTURING, codegen, producer="test_structuring",
    )
    handoff_function_ast_to_rewrite_8616(project, BASE, codegen)
    record_function_ast_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.REWRITE, codegen, producer="test_rewrite",
    )


def test_contract_gate_passes_with_current_evidence() -> None:
    """Actual AST publications and explicit handoff satisfy the final currency gate."""
    project, _function = _project(MOV_AX_BX_RET)
    codegen, _constant = _native_ast_fixture(project)
    codegen._inertia_stack_lane = SemanticLaneState(name="stack")
    _record_native_prefix(project)
    _publish_native_ast_pair(project, codegen)
    assert_pipeline_contracts_8616(codegen)



def test_repeated_independent_revisions_reanalyze_safely() -> None:
    """Repeated independent revisions reanalyze safely."""
    project, _function = _project(MOV_AX_BX_RET)
    record_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.ALIAS, producer="test"
    )
    project.loader.memory.store(BASE, MOV_AX_DX_RET)
    assert (
        function_stage_readiness_8616(
            project, BASE, FunctionLifecycleStage8616.STRUCTURING
        ).verdict
        is FunctionStageVerdict8616.STALE
    )

    record_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.ALIAS, producer="test"
    )
    readiness = function_stage_readiness_8616(
        project, BASE, FunctionLifecycleStage8616.STRUCTURING
    )
    assert readiness.verdict is FunctionStageVerdict8616.UNTRACKED


def test_in_place_evidence_mutation_without_rerecord_stales_dependent() -> None:
    """Mutating a recorded producer output revokes dependents silently."""
    project, _function = _project(MOV_AX_BX_RET)
    produced = SimpleNamespace(tag="original")
    record_function_stage_evidence_8616(
        project,
        BASE,
        FunctionLifecycleStage8616.TYPES,
        producer="types",
        outputs=(produced,),
    )
    record_function_stage_evidence_8616(
        project,
        BASE,
        FunctionLifecycleStage8616.STRUCTURING,
        producer="consumer",
        upstream=((FunctionLifecycleStage8616.TYPES, produced),),
    )
    assert (
        function_stage_readiness_8616(
            project, BASE, FunctionLifecycleStage8616.STRUCTURING
        ).verdict
        is FunctionStageVerdict8616.CURRENT
    )

    produced.tag = "mutated"

    readiness = function_stage_readiness_8616(
        project, BASE, FunctionLifecycleStage8616.STRUCTURING
    )
    assert readiness.verdict is FunctionStageVerdict8616.STALE
    assert readiness.failure is FunctionStageFailure8616.UPSTREAM_EVIDENCE_CHANGED


def test_source_observation_loss_revokes_current_evidence() -> None:
    """Losing live source observation revokes earlier binary currency."""
    project, _function = _project(MOV_AX_BX_RET)
    record_function_stage_evidence_8616(
        project,
        BASE,
        FunctionLifecycleStage8616.TYPES,
        producer="types",
        outputs=(SimpleNamespace(tag="t"),),
    )
    assert (
        function_stage_readiness_8616(
            project, BASE, FunctionLifecycleStage8616.TYPES
        ).verdict
        is FunctionStageVerdict8616.CURRENT
    )

    del project.kb.functions[BASE]

    readiness = function_stage_readiness_8616(
        project, BASE, FunctionLifecycleStage8616.TYPES
    )
    assert readiness.verdict is FunctionStageVerdict8616.UNKNOWN_REFUSE
    assert readiness.failure is FunctionStageFailure8616.SOURCE_UNAVAILABLE


def test_unproven_stage_observation_is_unknown_refuse() -> None:
    """Recorded observation without observable source is never CURRENT."""
    project = SimpleNamespace()
    for stage in FUNCTION_LIFECYCLE_STAGES_8616:
        evidence = record_function_stage_evidence_8616(
            project, BASE, stage, producer="unproven_observation"
        )
        assert evidence.source_revision is None
        status = function_stage_readiness_8616(project, BASE, stage)
        assert status.verdict is FunctionStageVerdict8616.UNKNOWN_REFUSE


def test_inherited_native_slots_invalidate_live_evidence() -> None:
    """A carrier's inherited fields participate in its current evidence."""
    from inertia.pipeline.function_readiness import (
        function_stage_readiness_8616,
        record_function_stage_evidence_8616,
    )

    class BaseEvidence:
        """Model the inherited portion of a slotted native carrier."""
        __slots__ = ("signed",)
        signed: bool

        def __init__(self) -> None:
            self.signed = True

    class DerivedEvidence(BaseEvidence):
        """Expose an additional native field beside the inherited field."""
        __slots__ = ("width",)
        width: int

        def __init__(self) -> None:
            super().__init__()
            self.width = 16

    project, _function = _project(MOV_AX_BX_RET)
    assert function_ssa_artifact_at_address_8616(project, BASE).artifact is not None
    output = DerivedEvidence()
    record_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.TYPES,
        producer="native_type_carrier", outputs=(output,),
    )
    assert function_stage_readiness_8616(
        project, BASE, FunctionLifecycleStage8616.TYPES,
    ).verdict is FunctionStageVerdict8616.CURRENT
    output.signed = False
    assert function_stage_readiness_8616(
        project, BASE, FunctionLifecycleStage8616.TYPES,
    ).verdict is FunctionStageVerdict8616.STALE


def test_native_consumption_requires_completed_stage_producers() -> None:
    """A native registry proves IR availability, never unexecuted later stages."""
    from inertia.pipeline.errors import PipelineHardError
    from inertia.pipeline.function_readiness import assert_function_stage_ready_8616

    project, _function = _project(MOV_AX_BX_RET)
    assert function_ssa_artifact_at_address_8616(project, BASE).artifact is not None
    ir = assert_function_stage_ready_8616(
        project, BASE, FunctionLifecycleStage8616.IR, layer="test_native_admission",
    )
    assert ir.verdict is FunctionStageVerdict8616.CURRENT
    with pytest.raises(PipelineHardError) as caught:
        assert_function_stage_ready_8616(
            project, BASE, FunctionLifecycleStage8616.TYPES, layer="test_native_admission",
        )
    assert caught.value.details["failure"] == FunctionStageFailure8616.STAGE_NOT_PRODUCED.value
    assert caught.value.details["blocking_stage"] == FunctionLifecycleStage8616.ALIAS.value


def test_untracked_model_keeps_its_independent_proof_path() -> None:
    """Native prerequisites do not manufacture binary requirements for models."""
    from inertia.pipeline.function_readiness import assert_function_stage_ready_8616

    result = assert_function_stage_ready_8616(
        SimpleNamespace(), BASE, FunctionLifecycleStage8616.TYPES, layer="test_model_admission",
    )
    assert result.verdict is FunctionStageVerdict8616.UNTRACKED


@pytest.mark.parametrize("unsupported_part", ["output", "input"])
def test_unsupported_evidence_cannot_publish_current_stage(unsupported_part: str) -> None:
    """Unknown output or consumed-input content must remain a typed non-result."""
    project, _function = _project(MOV_AX_BX_RET)
    assert function_ssa_artifact_at_address_8616(project, BASE).artifact is not None
    record_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.ALIAS, producer="test_unknown_evidence",
        outputs=(object(),) if unsupported_part == "output" else (1,),
        upstream=((FunctionLifecycleStage8616.IR, object()),) if unsupported_part == "input" else (),
    )
    own = function_stage_readiness_8616(project, BASE, FunctionLifecycleStage8616.ALIAS)
    assert own.verdict is FunctionStageVerdict8616.UNKNOWN_REFUSE
    assert own.failure is FunctionStageFailure8616.EVIDENCE_NOT_REPRESENTABLE
    dependent = function_stage_readiness_8616(project, BASE, FunctionLifecycleStage8616.TYPES)
    assert dependent.verdict is FunctionStageVerdict8616.UNKNOWN_REFUSE
    assert dependent.failure is FunctionStageFailure8616.EVIDENCE_NOT_REPRESENTABLE


def test_live_output_becoming_unsupported_revokes_current_stage() -> None:
    """Losing a supported live field cannot leave the producer or consumer current."""
    project, _function = _project(MOV_AX_BX_RET)
    output = SimpleNamespace(size=2)
    record_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.ALIAS,
        producer="test_live_evidence", outputs=(output,),
    )
    assert function_stage_readiness_8616(
        project, BASE, FunctionLifecycleStage8616.ALIAS,
    ).verdict is FunctionStageVerdict8616.CURRENT
    output.size = object()
    readiness = function_stage_readiness_8616(project, BASE, FunctionLifecycleStage8616.ALIAS)
    assert readiness.verdict is FunctionStageVerdict8616.UNKNOWN_REFUSE
    assert readiness.failure is FunctionStageFailure8616.EVIDENCE_NOT_REPRESENTABLE


def test_segment_space_inside_producer_output_is_representable() -> None:
    """Typed segment identity must survive the generic evidence publication boundary."""
    from inertia.ir import MemSpace

    evidence = record_function_stage_evidence_8616(
        SimpleNamespace(), BASE, FunctionLifecycleStage8616.ALIAS,
        producer="test_typed_segment_evidence", outputs=(SimpleNamespace(space=MemSpace.SS),),
    )
    assert evidence.failure is None


def test_unsupported_publication_requires_a_new_producer_record() -> None:
    """A later representable mutation cannot retroactively complete a failed publication."""
    project, _function = _project(MOV_AX_BX_RET)
    output = SimpleNamespace(size=object())
    record_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.ALIAS,
        producer="test_failed_publication", outputs=(output,),
    )
    output.size = 2
    refused = function_stage_readiness_8616(project, BASE, FunctionLifecycleStage8616.ALIAS)
    assert refused.verdict is FunctionStageVerdict8616.UNKNOWN_REFUSE
    assert refused.failure is FunctionStageFailure8616.EVIDENCE_NOT_REPRESENTABLE
    record_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.ALIAS,
        producer="test_reexecuted_producer", outputs=(output,),
    )
    assert function_stage_readiness_8616(
        project, BASE, FunctionLifecycleStage8616.ALIAS,
    ).verdict is FunctionStageVerdict8616.CURRENT


def test_deep_finite_output_stays_current_and_detects_leaf_mutation() -> None:
    """A finite provenance chain must remain complete and observe later leaf changes."""
    project, _function = _project(MOV_AX_BX_RET)
    leaf = SimpleNamespace(size=2)
    output = leaf
    for _index in range(32):
        output = SimpleNamespace(source=output)
    record_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.ALIAS,
        producer="test_finite_provenance", outputs=(output,),
    )
    assert function_stage_readiness_8616(
        project, BASE, FunctionLifecycleStage8616.ALIAS,
    ).verdict is FunctionStageVerdict8616.CURRENT
    leaf.size = 4
    changed = function_stage_readiness_8616(project, BASE, FunctionLifecycleStage8616.ALIAS)
    assert changed.verdict is FunctionStageVerdict8616.STALE
    assert changed.failure is FunctionStageFailure8616.UPSTREAM_EVIDENCE_CHANGED


def test_cyclic_dynamic_output_is_a_typed_non_result() -> None:
    """An opaque cycle must refuse without recursion or a guessed identity digest."""
    project, _function = _project(MOV_AX_BX_RET)
    output = SimpleNamespace()
    output.source = output
    record_function_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.ALIAS,
        producer="test_cyclic_provenance", outputs=(output,),
    )
    refused = function_stage_readiness_8616(project, BASE, FunctionLifecycleStage8616.ALIAS)
    assert refused.verdict is FunctionStageVerdict8616.UNKNOWN_REFUSE
    assert refused.failure is FunctionStageFailure8616.EVIDENCE_NOT_REPRESENTABLE


def test_native_final_gate_requires_actual_ast_publications() -> None:
    """A stage label cannot stand in for the structured producer output."""
    project, _function = _project(MOV_AX_BX_RET)
    _record_native_prefix(project)
    for stage in FUNCTION_LIFECYCLE_STAGES_8616[4:]:
        record_function_stage_evidence_8616(project, BASE, stage, producer="labels_only", outputs=(stage,))
    with pytest.raises(PipelineHardError) as caught:
        assert_function_stage_ready_8616(
            project, BASE, FunctionLifecycleStage8616.REWRITE, layer="final_native_stage_control",
        )
    assert caught.value.details["failure"] == FunctionStageFailure8616.AST_PUBLICATION_UNAVAILABLE.value


def test_native_final_gate_requires_actual_structuring_handoff() -> None:
    """Two snapshots without a recorded consumer cannot prove Rewrite completion."""
    project, _function = _project(MOV_AX_BX_RET)
    codegen, _constant = _native_ast_fixture(project)
    _record_native_prefix(project)
    for stage in FUNCTION_LIFECYCLE_STAGES_8616[4:]:
        record_function_ast_stage_evidence_8616(project, BASE, stage, codegen, producer="no_consumer")
    with pytest.raises(PipelineHardError) as caught:
        assert_pipeline_contracts_8616(codegen)
    assert caught.value.details["failure"] == FunctionStageFailure8616.AST_HANDOFF_REFUSED.value


def test_native_handoff_rejects_live_ast_changed_after_structuring() -> None:
    """A stale actual operand must block entry into Rewrite."""
    project, _function = _project(MOV_AX_BX_RET)
    codegen, constant = _native_ast_fixture(project)
    _record_native_prefix(project)
    record_function_ast_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.STRUCTURING, codegen, producer="structuring",
    )
    constant.value = 4
    with pytest.raises(PipelineHardError) as caught:
        handoff_function_ast_to_rewrite_8616(project, BASE, codegen)
    assert caught.value.details["verdict"] == FunctionStageVerdict8616.STALE.value
    assert caught.value.details["blocking_stage"] == FunctionLifecycleStage8616.STRUCTURING.value


def test_native_final_gate_detects_changes_after_rewrite_publication() -> None:
    """A later AST edit must revoke final admission while retaining its input."""
    project, _function = _project(MOV_AX_BX_RET)
    codegen, constant = _native_ast_fixture(project)
    _record_native_prefix(project)
    _publish_native_ast_pair(project, codegen)
    assert_pipeline_contracts_8616(codegen)
    constant.value = 4
    assert function_stage_readiness_8616(
        project, BASE, FunctionLifecycleStage8616.STRUCTURING,
    ).verdict is FunctionStageVerdict8616.CURRENT
    with pytest.raises(PipelineHardError) as caught:
        assert_pipeline_contracts_8616(codegen)
    assert caught.value.details["blocking_stage"] == FunctionLifecycleStage8616.REWRITE.value
    assert caught.value.details["verdict"] == FunctionStageVerdict8616.STALE.value


def test_rewrite_in_progress_cannot_reuse_an_old_final_publication() -> None:
    """Starting a new consuming run invalidates the earlier emission receipt."""
    project, _function = _project(MOV_AX_BX_RET)
    codegen, constant = _native_ast_fixture(project)
    _record_native_prefix(project)
    _publish_native_ast_pair(project, codegen)
    record_function_ast_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.STRUCTURING, codegen, producer="new_structuring",
    )
    handoff_function_ast_to_rewrite_8616(project, BASE, codegen)
    constant.value = 4
    with pytest.raises(PipelineHardError) as caught:
        assert_pipeline_contracts_8616(codegen)
    assert caught.value.details["failure"] == FunctionStageFailure8616.STAGE_NOT_PRODUCED.value
    record_function_ast_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.REWRITE, codegen, producer="new_rewrite",
    )
    assert_pipeline_contracts_8616(codegen)


def test_final_consumer_must_match_the_actual_published_ast() -> None:
    """A different AST at the same address cannot borrow producer readiness."""
    project, _function = _project(MOV_AX_BX_RET)
    producer, _constant = _native_ast_fixture(project)
    consumer, foreign_constant = _native_ast_fixture(project)
    _record_native_prefix(project)
    _publish_native_ast_pair(project, producer)
    assert_pipeline_contracts_8616(consumer)
    foreign_constant.value = 4
    with pytest.raises(PipelineHardError) as caught:
        assert_pipeline_contracts_8616(consumer)
    assert caught.value.details["failure"] == FunctionStageFailure8616.AST_CONSUMER_CHANGED.value
    assert_pipeline_contracts_8616(producer)


def test_unrepresentable_foreign_consumer_cannot_borrow_readiness() -> None:
    """Unknown consumer metadata must refuse even when the producer is current."""
    project, _function = _project(MOV_AX_BX_RET)
    producer, _constant = _native_ast_fixture(project)
    consumer, foreign_constant = _native_ast_fixture(project)
    _record_native_prefix(project)
    _publish_native_ast_pair(project, producer)
    foreign_constant.tags["unknown"] = object()
    with pytest.raises(PipelineHardError) as caught:
        assert_pipeline_contracts_8616(consumer)
    assert caught.value.details["failure"] == FunctionStageFailure8616.AST_CONSUMER_CHANGED.value
    assert caught.value.details["ast_failure"] == "field_unsupported"


def test_final_output_cannot_be_frozen_by_an_extra_handoff() -> None:
    """Final admission requires a live Rewrite output, not a consumed snapshot."""
    from inertia.pipeline.function_readiness import function_stage_evidence_map_8616
    from inertia.pipeline.structured_ast_output import StructuredASTPublication8616

    project, _function = _project(MOV_AX_BX_RET)
    codegen, constant = _native_ast_fixture(project)
    _record_native_prefix(project)
    _publish_native_ast_pair(project, codegen)
    record = function_stage_evidence_map_8616(project, BASE)[FunctionLifecycleStage8616.REWRITE]
    publication = next(item for item in record.live_outputs if isinstance(item, StructuredASTPublication8616))
    assert publication.handoff_to_rewrite(codegen) is None
    constant.value = 4
    with pytest.raises(PipelineHardError) as caught:
        assert_pipeline_contracts_8616(codegen)
    assert caught.value.details["failure"] == FunctionStageFailure8616.AST_PUBLICATION_UNAVAILABLE.value


def test_ast_diagnostics_cannot_promote_unknown_producer_data() -> None:
    """Serializable failure diagnostics cannot become successful output evidence."""
    project, _function = _project(MOV_AX_BX_RET)
    codegen, constant = _native_ast_fixture(project)
    _record_native_prefix(project)
    constant.tags["unknown"] = object()
    record = record_function_ast_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.STRUCTURING, codegen, producer="unknown_ast",
    )
    assert record.failure is FunctionStageFailure8616.EVIDENCE_NOT_REPRESENTABLE
    assert record.to_dict()["ast_outputs"]
    del constant.tags["unknown"]
    with pytest.raises(PipelineHardError) as caught:
        handoff_function_ast_to_rewrite_8616(project, BASE, codegen)
    assert caught.value.details["failure"] == FunctionStageFailure8616.EVIDENCE_NOT_REPRESENTABLE.value


def _request_native_rewrite_completion(project: object, codegen: object) -> None:
    """Exercise the real inner cleanup completion hook inside its outer producer."""
    from inertia.postprocess.decompiler_postprocess_stage import _postprocess_set_completion_state_8616
    from inertia.postprocess.pass_transaction import PostprocessPassTransactionState8616

    state = PostprocessPassTransactionState8616(baseline_summary=None, known_cycle_path=None)
    _postprocess_set_completion_state_8616(project, codegen, state)


def test_rewrite_completion_waits_for_final_producer_names() -> None:
    """A final naming edit belongs to the produced version; later edits revoke it."""
    project, _function = _project(MOV_AX_BX_RET)
    codegen, _constant = _native_ast_fixture(project)
    _record_native_prefix(project)
    record_function_ast_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.STRUCTURING, codegen, producer="test_structuring",
    )
    with readiness_owner.function_rewrite_production_scope_8616(project, BASE, codegen):
        _request_native_rewrite_completion(project, codegen)
        assert FunctionLifecycleStage8616.REWRITE not in readiness_owner.function_stage_evidence_map_8616(project, BASE)
        codegen.cfunc.name = "final_cleanup_name"
    assert_pipeline_contracts_8616(codegen)
    codegen.cfunc.name = "unowned_later_name"
    with pytest.raises(PipelineHardError):
        assert_pipeline_contracts_8616(codegen)


def test_rewrite_completion_exception_never_publishes_output() -> None:
    """An inner completion request cannot survive a failed outer producer."""
    project, _function = _project(MOV_AX_BX_RET)
    codegen, _constant = _native_ast_fixture(project)
    _record_native_prefix(project)
    record_function_ast_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.STRUCTURING, codegen, producer="test_structuring",
    )
    with (
        pytest.raises(RuntimeError),
        readiness_owner.function_rewrite_production_scope_8616(project, BASE, codegen),
    ):
        _request_native_rewrite_completion(project, codegen)
        raise RuntimeError("outer producer failed after inner cleanup")
    assert FunctionLifecycleStage8616.REWRITE not in readiness_owner.function_stage_evidence_map_8616(project, BASE)


def test_rewrite_completion_rechecks_consumed_input() -> None:
    """A changed earlier stage must refuse the pending completion at commit."""
    project, _function = _project(MOV_AX_BX_RET)
    codegen, _constant = _native_ast_fixture(project)
    _record_native_prefix(project)
    record_function_ast_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.STRUCTURING, codegen, producer="test_structuring",
    )
    with (
        pytest.raises(PipelineHardError),
        readiness_owner.function_rewrite_production_scope_8616(project, BASE, codegen),
    ):
        _request_native_rewrite_completion(project, codegen)
        record_function_stage_evidence_8616(
            project, BASE, FunctionLifecycleStage8616.TYPES,
            producer="changed_upstream", outputs=("changed_type_evidence",),
        )
    assert FunctionLifecycleStage8616.REWRITE not in readiness_owner.function_stage_evidence_map_8616(project, BASE)


def test_rewrite_completion_rejects_replaced_consumed_version() -> None:
    """An equivalent replacement cannot impersonate the version already consumed."""
    project, _function = _project(MOV_AX_BX_RET)
    codegen, _constant = _native_ast_fixture(project)
    _record_native_prefix(project)
    record_function_ast_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.STRUCTURING, codegen, producer="test_structuring",
    )
    with (
        pytest.raises(PipelineHardError),
        readiness_owner.function_rewrite_production_scope_8616(project, BASE, codegen),
    ):
        _request_native_rewrite_completion(project, codegen)
        record_function_ast_stage_evidence_8616(
            project, BASE, FunctionLifecycleStage8616.STRUCTURING, codegen,
            producer="replacement_structuring",
        )
    assert FunctionLifecycleStage8616.REWRITE not in readiness_owner.function_stage_evidence_map_8616(project, BASE)


def test_rewrite_completion_duplicate_request_discards_pending_output() -> None:
    """A producer failure cannot reuse its first incomplete completion request."""
    project, _function = _project(MOV_AX_BX_RET)
    codegen, _constant = _native_ast_fixture(project)
    _record_native_prefix(project)
    record_function_ast_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.STRUCTURING, codegen, producer="test_structuring",
    )
    with (
        pytest.raises(ValueError),
        readiness_owner.function_rewrite_production_scope_8616(project, BASE, codegen),
    ):
        _request_native_rewrite_completion(project, codegen)
        _request_native_rewrite_completion(project, codegen)
    assert FunctionLifecycleStage8616.REWRITE not in readiness_owner.function_stage_evidence_map_8616(project, BASE)


def test_rewrite_completion_cannot_commit_inherited_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """A queued parent request cannot become output authority in another process."""
    project, _function = _project(MOV_AX_BX_RET)
    codegen, _constant = _native_ast_fixture(project)
    _record_native_prefix(project)
    record_function_ast_stage_evidence_8616(
        project, BASE, FunctionLifecycleStage8616.STRUCTURING, codegen, producer="test_structuring",
    )
    original_pid = readiness_owner.getpid()
    with (
        pytest.raises(ValueError),
        monkeypatch.context() as patch,
        readiness_owner.function_rewrite_production_scope_8616(project, BASE, codegen),
    ):
        _request_native_rewrite_completion(project, codegen)
        patch.setattr(readiness_owner, "getpid", lambda: original_pid + 1)
    assert FunctionLifecycleStage8616.REWRITE not in readiness_owner.function_stage_evidence_map_8616(project, BASE)


@pytest.mark.parametrize("foreign", ("project", "coordinate", "generator"))
def test_rewrite_completion_rejects_foreign_producer(
    production_scope_case_8616: _RewriteProductionCase8616, foreign: str,
) -> None:
    """A render lease cannot enqueue completion for another output or function."""
    case = production_scope_case_8616
    project = SimpleNamespace() if foreign == "project" else case.project
    address = BASE + 1 if foreign == "coordinate" else BASE
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=BASE)) if foreign == "generator" else case.codegen
    with (
        readiness_owner.function_rewrite_production_scope_8616(case.project, BASE, case.codegen),
        pytest.raises(ValueError),
    ):
        readiness_owner.record_function_rewrite_completion_8616(
            project, address, codegen, producer="foreign_completion",
        )


@dataclass(slots=True)
class _RewriteProductionCase8616:
    """Model inputs and a prerequisite spy for rendering-authority controls."""

    project: SimpleNamespace
    codegen: SimpleNamespace
    sources: dict[int, dict[FunctionLifecycleStage8616, FunctionStageEvidence8616]]
    calls: list[tuple[object, int, object]]
    checks: list[FunctionLifecycleStage8616]


@pytest.fixture
def production_scope_case_8616(monkeypatch: pytest.MonkeyPatch) -> _RewriteProductionCase8616:
    """Keep source-version identity distinct from the contextual render lease."""
    project = SimpleNamespace()
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=BASE))
    evidence = FunctionStageEvidence8616(FunctionLifecycleStage8616.STRUCTURING, None, ("actual-input",), (), "test_structuring")
    case = _RewriteProductionCase8616(project, codegen, {id(project): {FunctionLifecycleStage8616.STRUCTURING: evidence}}, [], [])

    def handoff(p: object, addr: int, cg: object) -> None:
        """Observe the prerequisite check before contextual authority exists."""
        assert readiness_owner.function_render_required_stage_8616(p, cg) is FunctionLifecycleStage8616.REWRITE
        case.calls.append((p, addr, cg))

    def check_input(
        p: object, addr: int, stage: FunctionLifecycleStage8616, *, layer: str,
    ) -> FunctionStageReadiness8616:
        """Record the complete producer-input prerequisite separately from formatting."""
        assert p is case.project and addr == BASE
        case.checks.append(stage)
        return FunctionStageReadiness8616(addr, stage, FunctionStageVerdict8616.CURRENT)

    monkeypatch.setattr(readiness_owner, "assert_function_stage_ready_8616", check_input)
    monkeypatch.setattr(readiness_owner, "handoff_function_ast_to_rewrite_8616", handoff)
    monkeypatch.setattr(readiness_owner, "function_stage_evidence_map_8616", lambda p, addr: case.sources.get(id(p), {}))
    return case


def test_structuring_production_consumes_types_and_revokes_render_authority(
    production_scope_case_8616: _RewriteProductionCase8616,
) -> None:
    """An internal Structuring render checks Types without publishing Rewrite."""
    case = production_scope_case_8616
    evidence = FunctionStageEvidence8616(
        FunctionLifecycleStage8616.TYPES, None, ("types-input",), (), "test_types",
    )
    case.sources[id(case.project)] = {FunctionLifecycleStage8616.TYPES: evidence}
    with readiness_owner.function_structuring_production_scope_8616(case.project, BASE, case.codegen):
        assert readiness_owner.function_render_required_stage_8616(case.project, case.codegen) is FunctionLifecycleStage8616.TYPES
        assert readiness_owner.function_render_required_stage_8616(object(), case.codegen) is FunctionLifecycleStage8616.REWRITE
        case.sources[id(case.project)][FunctionLifecycleStage8616.TYPES] = FunctionStageEvidence8616(
            FunctionLifecycleStage8616.TYPES, None, ("replaced-input",), (), "test_types",
        )
        assert readiness_owner.function_render_required_stage_8616(case.project, case.codegen) is FunctionLifecycleStage8616.REWRITE
    assert case.checks == [FunctionLifecycleStage8616.TYPES, FunctionLifecycleStage8616.TYPES]
    assert readiness_owner.function_render_required_stage_8616(case.project, case.codegen) is FunctionLifecycleStage8616.REWRITE


def test_structuring_render_failure_cannot_return_cached_text(
    production_scope_case_8616: _RewriteProductionCase8616,
) -> None:
    """A failed internal renderer must fail instead of exposing old C text."""
    from inertia.structuring import decompiler_structuring_stage as structuring_owner

    case = production_scope_case_8616
    case.codegen.project = case.project
    case.codegen.text = "cached text"

    def failed_render(function: object) -> str:
        """Model an actual contract failure at the formatting boundary."""
        raise PipelineHardError("render contract probe")

    case.codegen.render_text = failed_render
    with pytest.raises(PipelineHardError, match="render contract probe"):
        structuring_owner._regenerate_structuring_text_safely_8616(case.codegen, context="test")
    assert case.codegen.text == "cached text"
    assert readiness_owner.function_render_required_stage_8616(case.project, case.codegen) is FunctionLifecycleStage8616.REWRITE


def test_rewrite_production_checked_handoff_precedes_internal_rendering(production_scope_case_8616: _RewriteProductionCase8616) -> None:
    """Internal formatting consumes checked input; final emission keeps Rewrite."""
    case = production_scope_case_8616
    assert readiness_owner.function_render_required_stage_8616(case.project, case.codegen) is FunctionLifecycleStage8616.REWRITE
    with readiness_owner.function_rewrite_production_scope_8616(case.project, BASE, case.codegen):
        assert case.calls == [(case.project, BASE, case.codegen)]
        assert readiness_owner.function_render_required_stage_8616(case.project, case.codegen) is FunctionLifecycleStage8616.TYPES
        assert case.checks == [FunctionLifecycleStage8616.STRUCTURING]
    assert readiness_owner.function_render_required_stage_8616(case.project, case.codegen) is FunctionLifecycleStage8616.REWRITE


def test_rewrite_production_exception_revokes_scope(production_scope_case_8616: _RewriteProductionCase8616) -> None:
    """A failed producer cannot leave reduced rendering prerequisites active."""
    case = production_scope_case_8616
    with (
        pytest.raises(RuntimeError, match="probe"),
        readiness_owner.function_rewrite_production_scope_8616(case.project, BASE, case.codegen),
    ):
        raise RuntimeError("probe")
    assert readiness_owner.function_render_required_stage_8616(case.project, case.codegen) is FunctionLifecycleStage8616.REWRITE


def test_rewrite_production_foreign_generator_project_or_coordinate_keeps_final_gate(production_scope_case_8616: _RewriteProductionCase8616) -> None:
    """An active producer's permission cannot authorize a different output."""
    case = production_scope_case_8616
    with readiness_owner.function_rewrite_production_scope_8616(case.project, BASE, case.codegen):
        assert readiness_owner.function_render_required_stage_8616(object(), case.codegen) is FunctionLifecycleStage8616.REWRITE
        assert readiness_owner.function_render_required_stage_8616(case.project, object()) is FunctionLifecycleStage8616.REWRITE
        case.codegen.cfunc.addr = BASE + 0x1000
        assert readiness_owner.function_render_required_stage_8616(case.project, case.codegen) is FunctionLifecycleStage8616.REWRITE


def test_rewrite_production_changed_input_cannot_borrow_new_proof(production_scope_case_8616: _RewriteProductionCase8616) -> None:
    """A replacement Structuring publication cannot attest an older producer."""
    case = production_scope_case_8616
    with readiness_owner.function_rewrite_production_scope_8616(case.project, BASE, case.codegen):
        case.sources[id(case.project)][FunctionLifecycleStage8616.STRUCTURING] = FunctionStageEvidence8616(FunctionLifecycleStage8616.STRUCTURING, None, ("new-input",), (), "test_structuring")
        assert readiness_owner.function_render_required_stage_8616(case.project, case.codegen) is FunctionLifecycleStage8616.REWRITE


def test_rewrite_production_copied_context_loses_authority_when_producer_exits(production_scope_case_8616: _RewriteProductionCase8616) -> None:
    """Copied execution contexts cannot retain a completed producer's lease."""
    case = production_scope_case_8616
    with readiness_owner.function_rewrite_production_scope_8616(case.project, BASE, case.codegen):
        saved = copy_context()
        assert saved.run(readiness_owner.function_render_required_stage_8616, case.project, case.codegen) is FunctionLifecycleStage8616.TYPES
    assert saved.run(readiness_owner.function_render_required_stage_8616, case.project, case.codegen) is FunctionLifecycleStage8616.REWRITE


def test_rewrite_production_inherited_process_context_has_no_producer_authority(production_scope_case_8616: _RewriteProductionCase8616, monkeypatch: pytest.MonkeyPatch) -> None:
    """A forked context needs its own checked producer instead of inherited authority."""
    case = production_scope_case_8616
    with readiness_owner.function_rewrite_production_scope_8616(case.project, BASE, case.codegen):
        original_pid = readiness_owner.getpid()
        monkeypatch.setattr(readiness_owner, "getpid", lambda: original_pid + 1)
        assert readiness_owner.function_render_required_stage_8616(case.project, case.codegen) is FunctionLifecycleStage8616.REWRITE


def test_rewrite_production_refused_input_never_installs_context(production_scope_case_8616: _RewriteProductionCase8616, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed handoff never authorizes any pending output rendering."""
    case = production_scope_case_8616

    def refuse(*_args: object) -> None:
        """Reject the input before any contextual authority is installed."""
        raise PipelineHardError("input refused", layer="test_production_scope", function_addr=BASE)

    monkeypatch.setattr(readiness_owner, "handoff_function_ast_to_rewrite_8616", refuse)
    with (
        pytest.raises(PipelineHardError),
        readiness_owner.function_rewrite_production_scope_8616(case.project, BASE, case.codegen),
    ):
        pytest.fail("producer must not start")
    assert readiness_owner.function_render_required_stage_8616(case.project, case.codegen) is FunctionLifecycleStage8616.REWRITE
