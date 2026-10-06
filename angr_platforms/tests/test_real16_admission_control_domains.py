"""Real16 call-graph admission consults the fetch domain for opaque control.

Layer: tests.
Responsibility: lock the boundary-proof fallback inside
``admit_call_graph`` — a structurally opaque ``control_ip`` on a verified
``control_domain`` block may be normalized only by the shared Z3 control
proof, and every absent, tampered or unprovable piece of evidence must keep
its typed refusal. Exact ``discovered == declared`` successor closure and
all shared deadline/step budgets are unchanged.
"""
from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from recursive_proof_fixtures.call_continuation_inputs import (
    TWO_CALL_CODE,
    make_two_call_inputs,
    swap_declared_continuations,
)
from recursive_proof_fixtures.entry_domain_inputs import _document

from tools.dosunit import straightline_ssa as S
from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.real16_call_contracts import initial_state
from tools.dosunit.real16_call_evidence import group_functions
from tools.dosunit.real16_call_graph_admission import (
    AdmissionLimits,
    AdmissionRefusalReason,
    AdmissionVerdict,
    SiteStatus,
    _Budget,
    _resolve_control,
    admit_call_graph,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain import (
    BoundDomainReason,
    prove_image_bound_real16_domain,
)
from tools.dosunit.recursive_proofs.real16_joint_construction import build_real16_joint_system
from tools.dosunit.recursive_proofs.recursive_joint_admission import JointRefusal, admit_joint_system
from tools.dosunit.recursive_proofs.recursive_joint_contracts import (
    JointReason,
    JointStepKind,
    JointStepPair,
    JointSystem,
)
from tools.dosunit.recursive_proofs.recursive_joint_proof import check_joint_system
from tools.dosunit.recursive_proofs.recursive_static_control import StaticControlReason

LIMITS = AdmissionLimits(deadline_ms=20_000)


def _documents(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build both independently-loaded MZ documents exactly as the fixture."""
    return (_document(tmp_path, TWO_CALL_CODE, "left"),
            _document(tmp_path, TWO_CALL_CODE, "right"))


def _recursive_record(document: dict[str, Any], delta: int) -> dict[str, Any]:
    """Select the recursive function's part record at one entry delta."""
    for record in document["functions"]:
        function = record.get("function", {})
        part = record.get("part", {})
        if function.get("name") == "recursive" and int(str(part.get("entry_delta")), 0) == delta:
            return record
    raise AssertionError(f"recursive record at delta {delta} missing")


def test_two_call_system_admits_both_graphs(tmp_path: Path) -> None:
    """Actual bytes: the CS-relative jump target is proven under the domain."""
    for document in _documents(tmp_path):
        report = admit_call_graph(document, "recursive", limits=LIMITS)
        assert report.verdict is AdmissionVerdict.ADMITTED, report.refusals
        assert len(report.sites) == 2
        assert all(site.status is SiteStatus.RESOLVED for site in report.sites)
        assert {site.fall_delta for site in report.sites} == {10, 15}
        assert report.graph is not None and report.analysis is not None


def test_admission_without_wall_clock_deadline(tmp_path: Path) -> None:
    """A disabled deadline keeps proof and near-CALL resolution working."""
    report = admit_call_graph(_documents(tmp_path)[0], "recursive",
                              limits=AdmissionLimits(deadline_ms=-1))
    assert report.verdict is AdmissionVerdict.ADMITTED, report.refusals


def test_missing_domain_marker_keeps_refusal(tmp_path: Path) -> None:
    """Absent ``control_domain``: the structural refusal is preserved."""
    document = copy.deepcopy(_documents(tmp_path)[0])
    source = _recursive_record(document, 0x0A)["source"]
    assert source.pop("control_domain") is not None
    report = admit_call_graph(document, "recursive", limits=LIMITS)
    assert report.verdict is AdmissionVerdict.INCOMPLETE
    assert any(refusal.reason is AdmissionRefusalReason.CONTROL_TRANSFER_UNSUPPORTED
               and refusal.delta == 10 for refusal in report.refusals)


def test_tampered_domain_marker_keeps_refusal(tmp_path: Path) -> None:
    """A corrupted fetch window cannot prove the normalized jump target."""
    document = copy.deepcopy(_documents(tmp_path)[0])
    marker = _recursive_record(document, 0x0A)["source"]["control_domain"]
    marker["head_linear"] = "0x130a"
    marker["terminal_linear"] = "0x130a"
    report = admit_call_graph(document, "recursive", limits=LIMITS)
    assert report.verdict is AdmissionVerdict.INCOMPLETE
    assert any(refusal.reason is AdmissionRefusalReason.CONTROL_TRANSFER_UNSUPPORTED
               and refusal.delta == 10 for refusal in report.refusals)


def test_false_declared_successor_cannot_be_proven(tmp_path: Path) -> None:
    """Normalizing only ever binds declared destinations; a false one refuses.

    The boundary proof binds a scalar control term to the destination
    decoded from the part's own declared transfer, so repointing the
    declaration makes the Z3 obligation unprovable and the structural
    opaque-control refusal survives — no success is manufactured.
    """
    document = copy.deepcopy(_documents(tmp_path)[0])
    transfer = _recursive_record(document, 0x0A)["source"]["transfer"]
    transfer["successors"] = [{"linear": "0x1202", "low16": "0x1202"}]
    report = admit_call_graph(document, "recursive", limits=LIMITS)
    assert report.verdict is AdmissionVerdict.INCOMPLETE
    assert any(refusal.delta == 10 for refusal in report.refusals)


def test_unprovable_control_term_keeps_opaque_refusal(tmp_path: Path) -> None:
    """An input-dependent control term cannot be proven; refusal retained."""
    document = _documents(tmp_path)[0]
    ctx = group_functions(document)["recursive"]
    block = ctx.blocks[10]
    state = S._compose_block_outputs(block, block["outputs"], initial_state())
    state["control_ip"] = {"op": "input", "name": "ax", "width": 16}
    budget = _Budget.start(AdmissionLimits(deadline_ms=20_000))
    result = _resolve_control(block, state, budget)
    assert not result.complete
    assert result.reason is StaticControlReason.OPAQUE


def test_exhausted_deadline_refuses(tmp_path: Path) -> None:
    """Zero remaining wall clock still refuses rather than admitting."""
    report = admit_call_graph(_documents(tmp_path)[0], "recursive",
                              limits=AdmissionLimits(deadline_ms=0))
    assert report.verdict is AdmissionVerdict.INCOMPLETE
    assert any(refusal.reason is AdmissionRefusalReason.DEADLINE_EXCEEDED
               for refusal in report.refusals)


def test_exhausted_step_budget_refuses(tmp_path: Path) -> None:
    """A trivially small step budget stops the walk with a typed refusal."""
    report = admit_call_graph(_documents(tmp_path)[0], "recursive",
                              limits=AdmissionLimits(deadline_ms=20_000, max_steps=4))
    assert report.verdict is AdmissionVerdict.INCOMPLETE
    assert any(refusal.reason is AdmissionRefusalReason.STEP_BUDGET_EXCEEDED
               for refusal in report.refusals)


def _joint_system(tmp_path: Path) -> JointSystem:
    """Build the actual two-call joint proposal through the production owner."""
    left, right = _documents(tmp_path)
    return build_real16_joint_system(left, right, "recursive")


def _step_with_view(system: JointSystem) -> JointStepPair:
    """The actual ``eb 03`` step must carry a bound proved control view."""
    for step in system.steps:
        if step.node.delta == 10:
            assert step.original_control is not None, "eb 03 step lost its proved view"
            return step
    raise AssertionError("no step retains a proved control view")


def _refuse(system: JointSystem) -> JointRefusal:
    """Admission must raise one typed refusal for corrupted dispatch evidence."""
    with pytest.raises(JointRefusal) as refused:
        admit_joint_system(system)
    return refused.value


def test_joint_system_keeps_raw_effects_with_proved_control_views(tmp_path: Path) -> None:
    """Raw ``control_ip`` stays untouched; the bound view only feeds dispatch."""
    system = _joint_system(tmp_path)
    step = _step_with_view(system)
    view = step.original_control
    assert view is not None and step.candidate_control is not None
    assert view.node == step.node and view.address == step.original_address
    assert view.raw == step.original["control_ip"]
    assert view.normalized["op"] == "const" and int(str(view.normalized["value"]), 16) == 0x120F
    admit_joint_system(system)


def test_joint_check_is_conditional_with_proved_frames(tmp_path: Path) -> None:
    """Admitted views do not promote the proof: model stays conditional."""
    report = check_joint_system(_joint_system(tmp_path), timeout_ms=120000)
    assert report.status is ProofStatus.CONDITIONAL
    assert report.reason is JointReason.CONDITIONAL_MODEL
    assert report.frames and all(frame.status is ProofStatus.PROVED for frame in report.frames)


def test_stale_raw_state_invalidates_proved_control_view(tmp_path: Path) -> None:
    """A state changed after the proof no longer matches the view's raw term."""
    system = _joint_system(tmp_path)
    step = _step_with_view(system)
    changed = dict(step.original)
    changed["control_ip"] = {"op": "const", "width": 32, "value": "0x120f"}
    corrupted = replace(system, steps=tuple(replace(s, original=changed) if s is step else s
                                            for s in system.steps))
    refused = _refuse(corrupted)
    assert refused.reason is JointReason.DISPATCH
    assert refused.detail == "proved control view no longer binds this paired effect"


def test_tampered_view_raw_refuses(tmp_path: Path) -> None:
    """A view claiming a different raw term cannot bind this effect."""
    system = _joint_system(tmp_path)
    step = _step_with_view(system)
    view = step.original_control
    assert view is not None
    forged = replace(view, raw={"op": "const", "width": 32, "value": "0x120f"})
    corrupted = replace(system, steps=tuple(replace(s, original_control=forged) if s is step else s
                                            for s in system.steps))
    with pytest.raises(JointRefusal):
        admit_joint_system(corrupted)


def test_tampered_view_destination_refuses(tmp_path: Path) -> None:
    """A normalized term that misses the declared successors cannot dispatch."""
    system = _joint_system(tmp_path)
    step = _step_with_view(system)
    view = step.original_control
    assert view is not None
    wrong = replace(view, normalized={"op": "const", "width": 32, "value": "0x1200"})
    corrupted = replace(system, steps=tuple(replace(s, original_control=wrong) if s is step else s
                                            for s in system.steps))
    with pytest.raises(JointRefusal):
        admit_joint_system(corrupted)


def test_grafted_view_from_another_step_refuses(tmp_path: Path) -> None:
    """A view proved for one node cannot dispatch another step's control."""
    system = _joint_system(tmp_path)
    step = _step_with_view(system)
    view = step.original_control
    assert view is not None
    other = next(s for s in system.steps
                 if s is not step and s.kind is not JointStepKind.RETURN)
    corrupted = replace(system, steps=tuple(replace(s, original_control=view)
                                            if s is other else s for s in system.steps))
    with pytest.raises(JointRefusal):
        admit_joint_system(corrupted)


def test_tampered_view_domain_or_model_refuses(tmp_path: Path) -> None:
    """Marker-window or owner-model tampering invalidates the view."""
    system = _joint_system(tmp_path)
    step = _step_with_view(system)
    view = step.original_control
    assert view is not None
    bad_domain = replace(view, domain={**view.domain, "head_linear": "0x9999"})
    bad_model = replace(view, model_hash="0" * 64)
    for forged in (bad_domain, bad_model):
        corrupted = replace(system, steps=tuple(replace(s, original_control=forged)
                                                if s is step else s for s in system.steps))
        with pytest.raises(JointRefusal):
            admit_joint_system(corrupted)


def test_forged_view_block_refuses(tmp_path: Path) -> None:
    """A swapped or stripped proving block cannot re-verify the term."""
    system = _joint_system(tmp_path)
    step = _step_with_view(system)
    view = step.original_control
    assert view is not None
    source = dict(view.block["source"])
    stripped = {**view.block, "source": {key: value for key, value in source.items()
                                         if key != "control_domain"}}
    mislabeled = {**view.block, "source": {**source, "machine_code_sha256": "0" * 64}}
    for forged in (replace(view, block=stripped), replace(view, block=mislabeled)):
        corrupted = replace(system, steps=tuple(replace(s, original_control=forged)
                                                if s is step else s for s in system.steps))
        with pytest.raises(JointRefusal):
            admit_joint_system(corrupted)


def test_equivalent_normalized_representation_still_dispatches(tmp_path: Path) -> None:
    """A different spelling of the proved destination remains valid.

    Canonical term spelling is not required: the consumer re-proves ``raw``
    under the bound block/domain and resolves the view's term itself, so a
    semantically equivalent representation of the same destination keeps
    the identical dispatch verdict.
    """
    system = _joint_system(tmp_path)
    step = _step_with_view(system)
    view = step.original_control
    assert view is not None
    equivalent = {"op": "add", "width": 32,
                  "args": [{"op": "const", "width": 32, "value": "0x120e"},
                           {"op": "const", "width": 32, "value": "0x1"}]}
    forged = replace(view, normalized=equivalent)
    corrupted = replace(system, steps=tuple(replace(s, original_control=forged)
                                            if s is step else s for s in system.steps))
    assert admit_joint_system(corrupted) == admit_joint_system(system)


def test_repointed_successors_and_forged_normalized_refuse(tmp_path: Path) -> None:
    """A false normalized claim cannot survive the consumer's re-proof.

    Corrupt the ``eb 03`` step's declared successors to the CALL head,
    remove the now-unreachable RET node coherently, and forge both views'
    ``normalized`` to that destination — every metadata binding stays
    genuine. The fresh boundary proof still derives the real ``0x120f``
    destination, which cannot equal the corrupted dispatch set.
    """
    system = _joint_system(tmp_path)
    step = _step_with_view(system)
    call_head = next(s.node for s in system.steps if s.node.delta == 0x0C)
    continuation_step = next(s for s in system.steps
                             if s.continuation is not None and s.continuation.delta == 0x0F)
    assert step.original_control is not None and step.candidate_control is not None
    forged_const = {"op": "const", "width": 32, "value": "0x120c"}
    steps = []
    for current in system.steps:
        if current.node.delta == 0x0F:
            continue
        if current is step:
            current = replace(current, successors=(call_head,),
                              original_control=replace(step.original_control,
                                                       normalized=forged_const),
                              candidate_control=replace(step.candidate_control,
                                                        normalized=forged_const))
        elif current is continuation_step:
            current = replace(current, continuation=step.node)
        steps.append(current)
    corrupted = replace(system, steps=tuple(steps),
                        expected_nodes=tuple(current.node for current in steps))
    refused = _refuse(corrupted)
    assert refused.reason is JointReason.DISPATCH


def test_actual_image_bound_domain_discharges(tmp_path: Path) -> None:
    """Full source/domain binding still proves raw joint effects unchanged."""
    inputs = make_two_call_inputs(tmp_path)
    receipt = prove_image_bound_real16_domain(*inputs)
    assert receipt.status is ProofStatus.PROVED and receipt.reason is BoundDomainReason.DISCHARGED


def test_swapped_continuations_stay_countermodel(tmp_path: Path) -> None:
    """Swapped call metadata must not become conditional or proved."""
    inputs = make_two_call_inputs(tmp_path)
    corrupted = swap_declared_continuations(inputs.system)
    assert admit_joint_system(corrupted) == admit_joint_system(inputs.system)
    receipt = prove_image_bound_real16_domain(corrupted, *inputs[1:])
    assert receipt.status is ProofStatus.PROVED, receipt
    report = check_joint_system(corrupted, timeout_ms=120000)
    assert report.status is ProofStatus.UNKNOWN and report.reason is JointReason.COUNTERMODEL
    assert report.proof.counters.failure_count > 0
