"""Join the IR modular stack-word use proof into production input typing.

Layer: Tests.
Responsibility: verify binary-derived modular input classification and retained
refusals through the production collection/preflight boundaries.

These tests exercise the real-byte collection path: a callee whose only use
of its stack words is sign-insensitive modular arithmetic through the AX
return must classify proven VALUE inputs as SIGN_INSENSITIVE even when no
branch condition exists. The tests never infer source signedness, pointer
type, or a return expression.
"""

from __future__ import annotations

import importlib
import io
from dataclasses import replace
from types import ModuleType, SimpleNamespace
from typing import Any, Protocol, cast

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import (
    CallsiteArgumentClass8616,
    CallsitePushSourceKind8616,
    CallsiteSummary8616,
)
from inertia.ir import (
    AddressStatus,
    IRAddress,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.condition_ir import ConditionIR, ConditionOp
from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactVerdict8616,
)
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.lowering.callee_argument_count_evidence import (
    CalleeArgumentCountEvidence8616,
    CalleeArgumentCountVerdict8616,
)
from inertia.lowering.callee_callsite_census import (
    CalleeCallsiteFact8616,
)
from inertia.lowering.condition_argument_type_facts import (
    collect_condition_argument_type_facts_8616,
)
from inertia.lowering.interprocedural_storage_collection_contracts import (
    StorageTrialCollectionFailureKind8616,
    StorageTrialCollectionVerdict8616,
)
from inertia.lowering.interprocedural_storage_contracts import (
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
)
from inertia.lowering.interprocedural_storage_input_preflight import (
    classify_callsite_inputs_before_ssa_8616,
)
from inertia.lowering.interprocedural_storage_reaching_defs import (
    physical_call_argument_8616,
)
from inertia.lowering.interprocedural_storage_trial_collection import (
    collect_function_input_storage_trials_8616,
)
from inertia.lowering.interprocedural_storage_trial_types import (
    classify_input_argument_8616,
)

from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from inertia.semantics.call_stack_effect_pipeline import (
    semantic_function_ssa_artifact_at_address_8616,
)

_CALLER_ADDR = 0x1000
_CALLER_END = 0x100B
_CALLEE_ADDR = 0x1010
_CALLEE_END = 0x1026
# push 2; push 1; call 0x1010; add sp,4; ret
_CALLER_CODE = bytes.fromhex("6a02 6a01 e80900 83c404 c3")
# push bp; mov bp,sp; push di; push si; mov ax,[bp+6]; shl ax,1;
# add ax,[bp+4]; jmp $+3; pop si; pop di; mov sp,bp; pop bp; ret
_CALLEE_CODE = bytes.fromhex(
    "55 8b ec 57 56 8b 46 06 d1 e0 03 46 04 e9 00 00 "
    "5e 5f 8b e5 5d c3"
)
_SIGNED_CALLEE_CODE = _CALLEE_CODE.replace(
    bytes.fromhex("d1 e0"), bytes.fromhex("d1 f8")
)
_BASE_STORAGE = IRAddress(
    space=MemSpace.SS,
    base=("bp",),
    offset=4,
    size=2,
    status=AddressStatus.STABLE,
    segment_origin=SegmentOrigin.DEFAULTED,
)
_INDEX_STORAGE = replace(_BASE_STORAGE, offset=6)


class _EvidenceProjectFixture8616(Protocol):
    """Typed projection of metadata attached to the third-party angr fixture."""

    _inertia_caller_function_ranges_8616: tuple[tuple[int, int], ...]
    _inertia_callee_argument_count_evidence_8616: dict[int, CalleeArgumentCountEvidence8616]
    _inertia_function_ssa_artifacts_8616: dict[int, SSAFunctionArtifact]


def _modular_facts_module() -> ModuleType:
    """Import the staged join owner lazily so old-API tests stay importable."""
    return importlib.import_module(
        "inertia.lowering.modular_argument_type_facts"
    )


def _project(callee_code: bytes = _CALLEE_CODE) -> angr.Project:
    """Build one blob image with a real caller and the modular callee."""
    image = bytearray(0x40)
    image[0 : len(_CALLER_CODE)] = _CALLER_CODE
    callee_offset = _CALLEE_ADDR - 0x1000
    image[callee_offset : callee_offset + len(callee_code)] = callee_code
    return angr.Project(
        io.BytesIO(bytes(image)),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": _CALLER_ADDR,
        },
        auto_load_libs=False,
        simos="DOS",
    )


def _boundary(project: angr.Project, start: int, end: int) -> ExactFunctionRangeBoundary8616:
    boundary = exact_function_range_boundary_8616(project, start, end)
    assert boundary is not None
    return boundary


def _summary(
    *,
    logical_classes: tuple[CallsiteArgumentClass8616, ...] = (),
) -> CallsiteSummary8616:
    """One two-word near cdecl callsite into the modular callee."""
    return CallsiteSummary8616(
        callsite_addr=0x1004,
        target_addr=_CALLEE_ADDR,
        return_addr=0x1007,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=None,
        push_arg_sources=(
            (CallsitePushSourceKind8616.IMMEDIATE.value, 2),
            (CallsitePushSourceKind8616.IMMEDIATE.value, 1),
        ),
        push_arg_instruction_addrs=(0x1000, 0x1002),
        logical_arg_classes=logical_classes,
    )


def _census_project(
    callee_code: bytes = _CALLEE_CODE,
    *,
    register_ssa: bool = True,
    register_range: bool = True,
    summary: CallsiteSummary8616 | None = None,
) -> angr.Project:
    """Attach the closed caller census and callee SSA/boundary evidence."""
    project = _project(callee_code)
    evidence_project = cast(_EvidenceProjectFixture8616, project)
    summary = _summary() if summary is None else summary
    caller_boundary = _boundary(project, _CALLER_ADDR, _CALLER_END)
    callee_boundary = _boundary(project, _CALLEE_ADDR, _CALLEE_END)
    if register_range:
        evidence_project._inertia_caller_function_ranges_8616 = (
            (_CALLEE_ADDR, _CALLEE_END),
        )
    if register_ssa:
        resolution = semantic_function_ssa_artifact_at_address_8616(
            project, _CALLEE_ADDR, function=callee_boundary,
        )
        assert resolution.verdict is FunctionSSAArtifactVerdict8616.PROVEN
        assert resolution.artifact is not None
    fact = CalleeCallsiteFact8616(
        evidence_project=project,
        caller_function=caller_boundary,
        evidence_target_addr=_CALLEE_ADDR,
        caller_addr=_CALLER_ADDR,
        callsite_addr=summary.callsite_addr,
        summary=summary,
    )
    evidence_project._inertia_callee_argument_count_evidence_8616 = {
        _CALLEE_ADDR: CalleeArgumentCountEvidence8616(
            target_addr=_CALLEE_ADDR,
            verdict=CalleeArgumentCountVerdict8616.CONSISTENT,
            argument_count=2,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            callsite_addrs=(summary.callsite_addr,),
            callsite_summaries=(summary,),
            callsite_facts=(fact,),
        ),
    }
    return project


def _empty_codegen() -> SimpleNamespace:
    """Return codegen without any branch-condition signedness evidence."""
    return SimpleNamespace(_inertia_typed_conditions=())


def _condition_codegen(*ops: ConditionOp, offset: int = 4) -> SimpleNamespace:
    """Return codegen carrying exact BP+offset condition facts."""
    return SimpleNamespace(
        _inertia_typed_conditions=tuple(
            ConditionIR(
                op,
                IRValue(MemSpace.SS, name="bp", offset=offset, size=2),
                IRValue(MemSpace.CONST, const=0, size=2),
                src_insn=0x1010,
                block_addr=0x1010,
            )
            for op in ops
        ),
    )


def _registered_artifact(project: angr.Project) -> SSAFunctionArtifact:
    """Return the registered callee Semantics SSA artifact."""
    artifacts = cast(_EvidenceProjectFixture8616, project)._inertia_function_ssa_artifacts_8616
    artifact = artifacts[_CALLEE_ADDR]
    assert isinstance(artifact, SSAFunctionArtifact)
    return artifact


def test_modular_input_join_materializes_sign_insensitive_value_trials() -> None:
    """Proven modular word use replaces the no-condition refusal."""
    project = _census_project()

    result = collect_function_input_storage_trials_8616(
        project, _empty_codegen(), _CALLEE_ADDR,
    )

    assert result.complete
    assert result.verdict is StorageTrialCollectionVerdict8616.PROVEN
    assert result.stats.complete
    trials = result.trials.callsites[0].arguments
    assert len(trials) == 4
    assert {trial.logical_index for trial in trials} == {0, 1}
    assert all(
        trial.signedness is StorageTrialSignedness8616.SIGN_INSENSITIVE
        for trial in trials
    )
    assert all(
        trial.value_class is StorageTrialValueClass8616.VALUE for trial in trials
    )


def test_signed_operation_callee_retains_signedness_refusal() -> None:
    """A sign-dependent use refuses exactly like missing condition evidence."""
    project = _census_project(_SIGNED_CALLEE_CODE)

    result = collect_function_input_storage_trials_8616(
        project, _empty_codegen(), _CALLEE_ADDR,
    )

    assert result.verdict is StorageTrialCollectionVerdict8616.UNKNOWN_REFUSE
    assert not result.complete
    assert result.trials.callsites == ()
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1
    kinds = {failure.kind for failure in result.failures}
    assert kinds == {StorageTrialCollectionFailureKind8616.SIGNEDNESS_UNKNOWN}


def test_known_condition_signedness_is_not_overridden() -> None:
    """A proven signed condition keeps SIGNED; the other word joins modular."""
    project = _census_project()

    result = collect_function_input_storage_trials_8616(
        project, _condition_codegen("slt"), _CALLEE_ADDR,
    )

    assert result.complete
    trials = result.trials.callsites[0].arguments
    by_index = {trial.logical_index: trial for trial in trials}
    assert by_index[0].signedness is StorageTrialSignedness8616.SIGNED
    assert by_index[1].signedness is StorageTrialSignedness8616.SIGN_INSENSITIVE
    assert all(
        trial.value_class is StorageTrialValueClass8616.VALUE for trial in trials
    )


def test_condition_conflict_is_not_rescued_by_modular_proof() -> None:
    """Conflicting condition evidence still refuses; no modular rescue."""
    project = _census_project()
    codegen = _condition_codegen("slt", "ult")

    result = collect_function_input_storage_trials_8616(
        project, codegen, _CALLEE_ADDR,
    )

    assert collect_condition_argument_type_facts_8616(codegen).failure_count == 1
    assert result.verdict is StorageTrialCollectionVerdict8616.CONFLICT
    assert result.trials.callsites == ()
    kinds = {failure.kind for failure in result.failures}
    assert kinds == {StorageTrialCollectionFailureKind8616.SIGNEDNESS_CONFLICT}


def test_independent_pointer_classification_is_preserved() -> None:
    """A proven pointer input keeps POINTER/NOT_APPLICABLE untouched."""
    summary = _summary(
        logical_classes=(
            CallsiteArgumentClass8616.POINTER,
            CallsiteArgumentClass8616.VALUE,
        ),
    )
    project = _census_project(summary=summary)

    result = collect_function_input_storage_trials_8616(
        project, _empty_codegen(), _CALLEE_ADDR,
    )

    assert result.complete
    trials = result.trials.callsites[0].arguments
    by_index = {trial.logical_index: trial for trial in trials}
    assert by_index[0].value_class is StorageTrialValueClass8616.POINTER
    assert by_index[0].signedness is StorageTrialSignedness8616.NOT_APPLICABLE
    assert by_index[1].value_class is StorageTrialValueClass8616.VALUE
    assert by_index[1].signedness is StorageTrialSignedness8616.SIGN_INSENSITIVE


def test_unregistered_callee_ssa_retains_original_refusal() -> None:
    """Without a registered callee artifact the refusal is unchanged."""
    project = _census_project(register_ssa=False)

    result = collect_function_input_storage_trials_8616(
        project, _empty_codegen(), _CALLEE_ADDR,
    )

    assert result.verdict is StorageTrialCollectionVerdict8616.UNKNOWN_REFUSE
    assert result.trials.callsites == ()
    kinds = {failure.kind for failure in result.failures}
    assert kinds == {StorageTrialCollectionFailureKind8616.SIGNEDNESS_UNKNOWN}


def test_absent_callee_boundary_retains_original_refusal() -> None:
    """No boundary or range evidence means no proof and no rescue."""
    project = _census_project(register_range=False)

    result = collect_function_input_storage_trials_8616(
        project, _empty_codegen(), _CALLEE_ADDR,
    )

    assert result.verdict is StorageTrialCollectionVerdict8616.UNKNOWN_REFUSE
    assert result.trials.callsites == ()
    kinds = {failure.kind for failure in result.failures}
    assert kinds == {StorageTrialCollectionFailureKind8616.SIGNEDNESS_UNKNOWN}


def test_proof_owner_binds_callee_storage_boundary_and_artifact() -> None:
    """The proof result retains exact identities, not a bare verdict."""
    modular = _modular_facts_module()
    project = _census_project()
    facts = modular.ModularArgumentTypeFacts8616(project, _CALLEE_ADDR)

    proof = facts.proof_for_8616(_BASE_STORAGE)

    assert proof.complete
    assert proof.verdict is modular.ModularInputProofVerdict8616.PROVEN
    assert proof.callee_addr == _CALLEE_ADDR
    assert proof.storage == _BASE_STORAGE
    assert proof.proven_storage is not None
    assert proof.proven_storage.segment_origin is SegmentOrigin.PROVEN
    assert proof.proven_storage.offset == 4
    assert proof.boundary is not None and proof.boundary.addr == _CALLEE_ADDR
    assert proof.artifact is _registered_artifact(project)
    assert proof.proof is not None
    assert proof.proof.input_access_key == proof.access_key
    assert proof.access_key.function_addr == _CALLEE_ADDR
    assert isinstance(proof.proof.return_instruction_addr, int)
    assert proof.stats == modular.ModularInputProofStats8616(1, 1, 1, 1, 0)

    cached = facts.proof_for_8616(replace(_BASE_STORAGE, segment_origin=SegmentOrigin.PROVEN))
    assert cached is proof


def test_proof_owner_refuses_foreign_storage_and_callee() -> None:
    """Unrequested slots and other callees never produce borrowed proofs."""
    modular = _modular_facts_module()
    project = _census_project()
    facts = modular.ModularArgumentTypeFacts8616(project, _CALLEE_ADDR)

    wrong_slot = facts.proof_for_8616(replace(_BASE_STORAGE, offset=8))
    wrong_size = facts.proof_for_8616(replace(_BASE_STORAGE, size=4))
    foreign_space = facts.proof_for_8616(
        replace(_BASE_STORAGE, space=MemSpace.DS, base=())
    )
    foreign_callee = modular.ModularArgumentTypeFacts8616(
        project, 0x2000
    ).proof_for_8616(_BASE_STORAGE)

    assert wrong_slot.failure is modular.ModularInputProofFailure8616.ACCESS_IDENTITY_UNKNOWN
    assert not wrong_slot.complete
    assert wrong_size.failure is modular.ModularInputProofFailure8616.INPUT_STORAGE_UNPROVEN
    assert foreign_space.failure is modular.ModularInputProofFailure8616.INPUT_STORAGE_UNPROVEN
    assert foreign_callee.failure is modular.ModularInputProofFailure8616.CALLEE_BOUNDARY_UNPROVEN


def test_stale_foreign_artifact_never_supplies_a_proof() -> None:
    """An artifact bound to a different function cannot stand in."""
    modular = _modular_facts_module()
    project = _census_project()
    artifact = _registered_artifact(project)
    foreign = replace(artifact, function_addr=_CALLER_ADDR)
    cast(_EvidenceProjectFixture8616, project)._inertia_function_ssa_artifacts_8616[_CALLEE_ADDR] = foreign

    facts = modular.ModularArgumentTypeFacts8616(project, _CALLEE_ADDR)
    proof = facts.proof_for_8616(_BASE_STORAGE)

    assert proof.failure is modular.ModularInputProofFailure8616.CALLEE_SSA_UNPROVEN
    assert not proof.complete


def test_upstream_sign_dependent_and_call_effect_refusals_propagate() -> None:
    """Typed IR refusals surface as refusals, never as adopted evidence."""
    modular = _modular_facts_module()
    project = _census_project(_SIGNED_CALLEE_CODE)
    facts = modular.ModularArgumentTypeFacts8616(project, _CALLEE_ADDR)

    refused = facts.proof_for_8616(_INDEX_STORAGE)
    proven = facts.proof_for_8616(_BASE_STORAGE)

    assert refused.failure is modular.ModularInputProofFailure8616.UPSTREAM_PROOF_REFUSED
    assert refused.upstream_failure is not None
    assert refused.upstream_failure.value == "sign_dependent_operation"
    assert not refused.complete
    assert proven.complete

    artifact = _registered_artifact(project)
    first_block = artifact.blocks[0]
    broken = replace(
        first_block.instrs[0], op="CALL", dst=None, args=(),
    )
    mutated_block = replace(
        first_block, instrs=(broken, *first_block.instrs[1:]),
    )
    mutated = replace(
        artifact,
        blocks=(mutated_block, *artifact.blocks[1:]),
    )
    cast(_EvidenceProjectFixture8616, project)._inertia_function_ssa_artifacts_8616[_CALLEE_ADDR] = mutated
    stale_facts = modular.ModularArgumentTypeFacts8616(project, _CALLEE_ADDR)
    call_refusal = stale_facts.proof_for_8616(_BASE_STORAGE)
    assert call_refusal.failure is modular.ModularInputProofFailure8616.UPSTREAM_PROOF_REFUSED
    assert call_refusal.upstream_failure is not None
    assert call_refusal.upstream_failure.value == "call_effect_unknown"


def test_corrupt_predecessor_map_refuses_through_closed_cfg() -> None:
    """A stale artifact whose CFG no longer matches the boundary refuses."""
    modular = _modular_facts_module()
    project = _census_project()
    artifact = _registered_artifact(project)
    mutated = replace(artifact, predecessor_map={})
    cast(_EvidenceProjectFixture8616, project)._inertia_function_ssa_artifacts_8616[_CALLEE_ADDR] = mutated
    facts = modular.ModularArgumentTypeFacts8616(project, _CALLEE_ADDR)

    proof = facts.proof_for_8616(_BASE_STORAGE)

    assert proof.failure is modular.ModularInputProofFailure8616.UPSTREAM_PROOF_REFUSED
    assert proof.upstream_failure is not None
    assert proof.upstream_failure.value == "cfg_not_closed"
    assert not proof.complete


def test_foreign_proof_identity_does_not_classify_input() -> None:
    """A bare or foreign proof result cannot classify this exact slot."""
    modular = _modular_facts_module()
    project = _census_project()
    facts = modular.ModularArgumentTypeFacts8616(project, _CALLEE_ADDR)
    proven = facts.proof_for_8616(_BASE_STORAGE)
    assert proven.complete
    foreign = replace(proven, storage=replace(_BASE_STORAGE, offset=8))

    class _ForeignFacts8616:
        """Stub that always returns the foreign proof."""

        def proof_for_8616(self, storage: IRAddress) -> object:
            """Return the retained foreign proof regardless of the query."""
            return foreign

    summary = _summary()
    physical, failure = physical_call_argument_8616(summary, 0)
    assert failure is None and physical is not None
    result = classify_input_argument_8616(
        summary,
        physical,
        _BASE_STORAGE,
        0,
        2,
        collect_condition_argument_type_facts_8616(_empty_codegen()),
        None,
        cast(Any, _ForeignFacts8616()),
    )

    assert result.failure is StorageTrialCollectionFailureKind8616.SIGNEDNESS_UNKNOWN
    assert result.signedness is None


def test_proofs_run_once_per_storage_across_callsites(monkeypatch: pytest.MonkeyPatch) -> None:
    """Repeated caller sites share one proof per storage identity."""
    modular = _modular_facts_module()
    project = _census_project()
    calls: list[IRAddress] = []
    upstream = modular.prove_stack_argument_modular_return_use_8616

    def _counting(boundary: object, artifact: object, storage: IRAddress) -> object:
        calls.append(storage)
        return upstream(boundary, artifact, storage)

    monkeypatch.setattr(
        modular, "prove_stack_argument_modular_return_use_8616", _counting,
    )
    facts = modular.ModularArgumentTypeFacts8616(project, _CALLEE_ADDR)
    facts.proof_for_8616(_BASE_STORAGE)
    facts.proof_for_8616(_BASE_STORAGE)
    facts.proof_for_8616(_INDEX_STORAGE)

    assert len(calls) == 2
    assert facts.stats == modular.ModularInputProofStats8616(2, 2, 2, 2, 0)


def test_preflight_refuses_modular_proofs_bound_to_another_callee() -> None:
    """A valid modular proof cannot classify another requested callee's inputs."""
    modular = _modular_facts_module()
    project = _census_project()
    evidence_project = cast(_EvidenceProjectFixture8616, project)
    count = evidence_project._inertia_callee_argument_count_evidence_8616[_CALLEE_ADDR]
    fact = count.callsite_facts[0]
    assert fact.summary is not None
    facts = modular.ModularArgumentTypeFacts8616(project, _CALLEE_ADDR)

    result = classify_callsite_inputs_before_ssa_8616(
        _CALLEE_ADDR + 0x100,
        fact,
        fact.summary,
        (_BASE_STORAGE, _INDEX_STORAGE),
        collect_condition_argument_type_facts_8616(_empty_codegen()),
        None,
        facts,
    )

    assert not result.complete
    assert {
        failure.kind for failure in result.failures
    } == {StorageTrialCollectionFailureKind8616.SIGNEDNESS_UNKNOWN}
    assert facts.stats.raw_fact_count == 0
