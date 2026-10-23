"""Native controls for conditional call preservation through jump admission.

Layer: tests.
Responsibility: retain the incoming selector premise across a real backward
CALL and loop-back JMP without publishing an unconditional function proof.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from inertia.ir.entry_jump_domain import (
    EntryJumpDomainApplicationStatus8616,
    EntryJumpDomainRefusal8616,
    apply_entry_jump_domain_8616,
    prove_entry_jump_domains_8616,
)
from tests.ir.test_near_call_preservation import _CODE, _prove_step, _resolver, _surface
from tests.ir.test_x86_16_entry_jump_domain import _evidence

if TYPE_CHECKING:
    from inertia.ir.near_call_jump_scope import NearCallJumpScope8616
    from inertia.ir.vex_terminal_jump import TerminalJumpEvidence8616
    from tests.ir.test_near_call_preservation import _Surface

pytestmark = pytest.mark.decompiler


def test_native_call_loop_requires_explicit_scope() -> None:
    """The ordinary route cannot assume the incoming call's selector interval."""
    surface = _surface(_CODE[:-1] + b"\x90" * 13 + bytes.fromhex("ebee"), root_end=0x1022)
    block = next(block for block in surface.artifact.blocks
                 if any(i.addr == 0x1020 and i.op == "JMP" for i in block.instrs))
    proof = prove_entry_jump_domains_8616(
        surface.artifact, {block.addr: _evidence(0x1020, bytes.fromhex("ebee"))},
        project=surface.project,
    )
    assert not proof.admitted
    assert any(row.kind == EntryJumpDomainRefusal8616.CALL_ON_PATH.value
               for row in proof.refusals)


def _scoped_loop() -> tuple[_Surface, NearCallJumpScope8616, dict[int, TerminalJumpEvidence8616]]:
    """Build independently authenticated preservation for the native loop."""
    from inertia.ir.near_call_jump_scope import NearCallJumpScope8616

    surface = _surface(_CODE[:-1] + b"\x90" * 13 + bytes.fromhex("ebee"), root_end=0x1022)
    block = next(block for block in surface.artifact.blocks
                 if any(i.addr == 0x1020 and i.op == "JMP" for i in block.instrs))
    scope = NearCallJumpScope8616(
        project=surface.project, artifact=surface.artifact, context=surface.context,
        direct_target_resolver=_resolver(surface.project),
        preservations=(_prove_step(surface),),
    )
    return surface, scope, {block.addr: _evidence(0x1020, bytes.fromhex("ebee"))}


def test_conditional_call_loop_admits_only_with_same_scope() -> None:
    """Induction keeps CS across repeated calls but retains the root premise."""
    surface, scope, pending = _scoped_loop()
    proof = prove_entry_jump_domains_8616(
        surface.artifact, pending, project=surface.project, near_call_scope=scope,
    )
    assert proof.admitted_target_for(0x1020) == 0x1010, proof.to_dict()
    assert proof.near_call_scope is scope
    assert all(jump.near_call_scope is scope for jump in proof.admitted)
    omitted = apply_entry_jump_domain_8616(surface.artifact, proof)
    assert omitted.status is EntryJumpDomainApplicationStatus8616.STALE_INPUT
    foreign = apply_entry_jump_domain_8616(
        surface.artifact, proof, near_call_scope=replace(scope),
    )
    assert foreign.status is EntryJumpDomainApplicationStatus8616.STALE_INPUT
    applied = apply_entry_jump_domain_8616(surface.artifact, proof, near_call_scope=scope)
    assert applied.status is EntryJumpDomainApplicationStatus8616.APPLIED, applied.to_dict()
    assert applied.near_call_scope is scope


@pytest.mark.parametrize("corruption", ["missing", "duplicate", "context", "callee"])
def test_scope_requires_complete_same_context_call_census(corruption: str) -> None:
    """A conditional tag cannot excuse absent, duplicate or foreign evidence."""
    surface, scope, pending = _scoped_loop()
    if corruption == "missing":
        scope = replace(scope, preservations=())
    elif corruption == "duplicate":
        scope = replace(scope, preservations=scope.preservations * 2)
    elif corruption == "context":
        scope = replace(scope, context=replace(surface.context))
    else:
        scope = replace(scope, preservations=(replace(scope.preservations[0], callee=None),))
    proof = prove_entry_jump_domains_8616(
        surface.artifact, pending, project=surface.project, near_call_scope=scope,
    )
    assert not proof.admitted


def test_native_byte_mutation_revokes_scoped_application() -> None:
    """A retained call theorem must still authenticate native bytes on apply."""
    surface, scope, pending = _scoped_loop()
    proof = prove_entry_jump_domains_8616(
        surface.artifact, pending, project=surface.project, near_call_scope=scope,
    )
    assert proof.admitted
    surface.project.loader.memory.store(0x1011, b"\x00")
    result = apply_entry_jump_domain_8616(surface.artifact, proof, near_call_scope=scope)
    assert result.status is EntryJumpDomainApplicationStatus8616.STALE_INPUT


def test_final_native_check_cannot_revoke_context_unnoticed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The final callback must not change a previously consumed selector premise."""
    from inertia.ir import near_call_jump_scope as owner

    surface, scope, _ = _scoped_loop()
    original = owner.consume_native_near_call_entry_8616
    calls = 0

    def revoke_after_check(*args: object, **kwargs: object) -> bool:
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            object.__setattr__(surface.context, "selector_high", -1)
        return result

    monkeypatch.setattr(owner, "consume_native_near_call_entry_8616", revoke_after_check)
    assert not owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )


@pytest.mark.parametrize("mutation", ["instruction", "function_refusal", "scope_project", "scope_context"])
def test_final_native_check_cannot_mutate_shared_caller_graph(monkeypatch, mutation):
    """A final callback must not escape the detached census-wide graph seal."""
    from inertia.ir import near_call_jump_scope as owner
    from inertia.ir.core import IRRefusal

    surface, scope, _ = _scoped_loop()
    original = owner.consume_native_near_call_entry_8616
    calls = 0

    def change_after_check(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            if mutation == "instruction":
                instruction = next(i for b in surface.artifact.blocks for i in b.instrs if i.op != "CALL")
                object.__setattr__(instruction, "op", "CHANGED")
            elif mutation == "function_refusal":
                object.__setattr__(surface.artifact, "refusals", (
                    *surface.artifact.refusals, IRRefusal("changed", "late mutation", surface.artifact.function_addr),
                ))
            elif mutation == "scope_project":
                foreign = object()
                object.__setattr__(scope, "project", foreign)
                object.__setattr__(surface.boundary, "project", foreign)
            else:
                object.__setattr__(scope, "context", replace(surface.context))
        return result

    monkeypatch.setattr(owner, "consume_native_near_call_entry_8616", change_after_check)
    assert not owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )


def test_census_uses_two_shared_graph_captures(monkeypatch):
    """Caller census captures once per phase while per-step native proof still runs."""
    from inertia.ir import near_call_jump_scope as owner

    surface, scope, _ = _scoped_loop()
    original = owner.capture_immutable_source_graph_facts_8616
    captured = []

    def capture(*args, **kwargs):
        captured.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(owner, "capture_immutable_source_graph_facts_8616", capture)
    assert owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )
    assert captured == [surface.artifact.function_addr] * 2


def test_census_does_not_recapture_caller_inside_preservation_steps(monkeypatch):
    """Only the outer fresh census seal owns preservation caller graph capture.

    Staged per-step checks still fully authenticate native target/callee facts;
    none publishes authority before the final whole-census mutation seal.
    Standalone preservation consumption retains its independent snapshots.
    """
    from inertia.ir import near_call_jump_scope as owner
    from inertia.ir import near_call_preservation as preservation

    surface, scope, _ = _scoped_loop()
    original = preservation.capture_immutable_source_graph_facts_8616
    captured = []

    def capture(*args, **kwargs):
        captured.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(preservation, 'capture_immutable_source_graph_facts_8616', capture)
    assert owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )
    assert captured == []


def _scoped_two_call() -> tuple[_Surface, NearCallJumpScope8616]:
    """Build one authenticated scope over a two-CALL caller census."""
    from inertia.ir.near_call_jump_scope import NearCallJumpScope8616
    from inertia.ir.near_call_preservation import (
        ConditionalNearCallPreservationVerdict8616,
    )
    from inertia.semantics.conditional_near_call_target import (
        ConditionalNearCallTargetVerdict8616,
        prove_conditional_near_call_target_8616,
    )
    from inertia.semantics.direct_near_call_target_binding import (
        DirectNearCallCoordinates8616,
    )

    code = bytes.fromhex(
        "e80d00"  # 0x1000: incoming near CALL -> root 0x1010
        "9090909090"  # 0x1003: filler
        "c3"  # 0x1008: earlier leaf RET, external to the root range
        "90909090909090"  # 0x1009: filler
        "e8f5ff"  # 0x1010: first outgoing near CALL -> leaf 0x1008
        "e8f2ff"  # 0x1013: second outgoing near CALL -> leaf 0x1008
        "c3"  # 0x1016: root RET
    )
    surface = _surface(code, root_end=0x1017)
    second = next(
        instruction
        for candidate in surface.artifact.blocks
        for instruction in candidate.instrs
        if instruction.addr == 0x1013 and instruction.op == "CALL"
    )
    block2 = next(
        candidate for candidate in surface.artifact.blocks
        if any(instruction is second for instruction in candidate.instrs)
    )
    theorem2 = prove_conditional_near_call_target_8616(
        surface.project,
        artifact=surface.artifact,
        context=surface.context,
        block=block2,
        instruction=second,
        coordinates=DirectNearCallCoordinates8616(0x1013, 0x1016, 0x1008),
    )
    assert theorem2.verdict is ConditionalNearCallTargetVerdict8616.CONDITIONAL
    step2 = _prove_step(surface, theorem2, block=block2, instruction=second)
    assert step2.verdict is ConditionalNearCallPreservationVerdict8616.CONDITIONAL
    scope = NearCallJumpScope8616(
        project=surface.project,
        artifact=surface.artifact,
        context=surface.context,
        direct_target_resolver=_resolver(surface.project),
        preservations=(_prove_step(surface), step2),
    )
    return surface, scope


def test_two_call_census_uses_scope_owned_snapshots_only(monkeypatch):
    """Two staged steps share the scope's seals; no per-step graph capture."""
    from inertia.ir import near_call_jump_scope as owner
    from inertia.ir import near_call_preservation as preservation

    surface, scope = _scoped_two_call()
    preserve = preservation.capture_immutable_source_graph_facts_8616
    scoped = owner.capture_immutable_source_graph_facts_8616
    preservation_captured = []
    owner_captured = []

    def track_preservation(*args, **kwargs):
        preservation_captured.append(args[0])
        return preserve(*args, **kwargs)

    def track_owner(*args, **kwargs):
        owner_captured.append(args[0])
        return scoped(*args, **kwargs)

    monkeypatch.setattr(
        preservation, 'capture_immutable_source_graph_facts_8616',
        track_preservation,
    )
    monkeypatch.setattr(
        owner, 'capture_immutable_source_graph_facts_8616', track_owner,
    )
    assert owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )
    assert preservation_captured == []
    assert owner_captured == [surface.artifact.function_addr] * 2


@pytest.mark.parametrize("mutation", [
    "earlier_theorem", "earlier_step", "earlier_callee",
    "caller", "scope_project", "scope_context",
])
def test_final_callback_cannot_mutate_earlier_census_evidence(monkeypatch, mutation):
    """The final entry callback cannot rewrite already consumed census evidence."""
    from inertia.ir import near_call_jump_scope as owner

    surface, scope = _scoped_two_call()
    first = scope.preservations[0]
    original = owner.consume_native_near_call_entry_8616
    calls = 0

    def mutate_after_check(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            if mutation == "earlier_theorem":
                object.__setattr__(first.theorem, "selector_high", -1)
            elif mutation == "earlier_step":
                object.__setattr__(first, "callsite_addr", -1)
            elif mutation == "earlier_callee":
                object.__setattr__(
                    first.callee, "raw_fact_count",
                    first.callee.raw_fact_count + 1,
                )
            elif mutation == "caller":
                instruction = next(
                    i for b in surface.artifact.blocks
                    for i in b.instrs if i.op != "CALL"
                )
                object.__setattr__(instruction, "op", "CHANGED")
            elif mutation == "scope_project":
                foreign = object()
                object.__setattr__(scope, "project", foreign)
                object.__setattr__(surface.boundary, "project", foreign)
            else:
                object.__setattr__(scope, "context", replace(surface.context))
        return result

    monkeypatch.setattr(
        owner, "consume_native_near_call_entry_8616", mutate_after_check,
    )
    assert not owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )


@pytest.mark.parametrize("mutation", [
    "same_theorem", "earlier_theorem", "earlier_callee", "caller",
])
def test_step_callback_cannot_mutate_census_evidence_unnoticed(monkeypatch, mutation):
    """A step's staged target preflight cannot rewrite census evidence."""
    from inertia.ir import near_call_jump_scope as owner
    from inertia.semantics import conditional_near_call_target as target_owner

    surface, scope = _scoped_two_call()
    original = target_owner.prove_direct_near_call_target_binding_at_coordinates_8616
    calls = 0

    def corrupt_last_staged(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            if mutation == "same_theorem":
                object.__setattr__(
                    scope.preservations[1].theorem, "selector_high", -1,
                )
            elif mutation == "earlier_theorem":
                object.__setattr__(
                    scope.preservations[0].theorem, "selector_high", -1,
                )
            elif mutation == "earlier_callee":
                object.__setattr__(
                    scope.preservations[0].callee, "raw_fact_count",
                    scope.preservations[0].callee.raw_fact_count + 1,
                )
            else:
                instruction = next(
                    i for b in surface.artifact.blocks
                    for i in b.instrs if i.op != "CALL"
                )
                object.__setattr__(instruction, "op", "CHANGED")
        return result

    monkeypatch.setattr(
        target_owner,
        "prove_direct_near_call_target_binding_at_coordinates_8616",
        corrupt_last_staged,
    )
    assert not owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )


def test_census_rebinds_root_once_without_inner_graph_capture(monkeypatch):
    """One raw-root rebind per census; no target-owner graph captures."""
    from inertia.ir import near_call_jump_scope as owner
    from inertia.semantics import conditional_near_call_target as target_owner

    surface, scope = _scoped_two_call()
    rebind = owner._rebind_raw_root_8616
    capture = target_owner.capture_immutable_source_graph_facts_8616
    calls = []

    def seen_rebind(*args, **kwargs):
        calls.append("rebind")
        return rebind(*args, **kwargs)

    def seen_capture(*args, **kwargs):
        calls.append("capture")
        return capture(*args, **kwargs)

    monkeypatch.setattr(owner, "_rebind_raw_root_8616", seen_rebind)
    monkeypatch.setattr(target_owner, "_rebind_raw_root_8616", seen_rebind)
    monkeypatch.setattr(
        target_owner, "capture_immutable_source_graph_facts_8616",
        seen_capture,
    )
    assert owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )
    assert calls.count("rebind") == 1
    assert calls.count("capture") == 0


@pytest.mark.parametrize("forgery", ["shape", "stats", "target_addr"])
def test_forged_retained_theorem_refuses_in_census(monkeypatch, forgery):
    """An intact-identity theorem with false derived facts must refuse.

    Identity fields (context/artifact/block/instruction) stay identical;
    only the arithmetic/statistical surface is forged, so record and
    identity gates alone cannot catch it — the final callback-free
    derivation must.
    """
    from inertia.ir import near_call_jump_scope as owner

    surface, scope = _scoped_two_call()
    first = scope.preservations[0]
    theorem = first.theorem
    if forgery == "shape":
        forged = replace(
            theorem,
            shape=replace(
                theorem.shape, displacement=theorem.shape.displacement ^ 0x1
            ),
        )
    elif forgery == "stats":
        forged = replace(
            theorem,
            stats=replace(
                theorem.stats,
                classified_fact_count=theorem.stats.classified_fact_count + 1,
            ),
        )
    else:
        forged = replace(theorem, target_addr=theorem.target_addr ^ 0x10)
    forged_scope = replace(
        scope, preservations=(replace(first, theorem=forged), *scope.preservations[1:]),
    )
    assert not owner.authenticate_near_call_jump_scope_8616(
        forged_scope, project=surface.project, artifact=surface.artifact,
    )


def test_final_derivation_sees_restored_ir_not_staged_transient(monkeypatch):
    """Mutation-then-restore during a callback leaves an admissible census.

    Corrupting a *different* call's derivation input only inside one
    staged preflight — restoring it before returning — leaves the final
    rooted IR identical, so the callback-free final pass must derive from
    that restored state and compare every retained theorem exactly once
    per call, rather than trusting any transient staged view.
    """
    from inertia.ir import near_call_jump_scope as owner
    from inertia.ir.core import IRValue, MemSpace
    from inertia.semantics import conditional_near_call_target as target_owner

    surface, scope = _scoped_two_call()
    preflight = target_owner.prove_direct_near_call_target_binding_at_coordinates_8616
    equal = target_owner._conditional_facts_equal_8616
    other_call = scope.preservations[1].theorem.instruction
    derived = []

    calls = 0

    def corrupt_then_restore(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls != 1:
            return preflight(*args, **kwargs)
        saved = other_call.args[0]
        object.__setattr__(
            other_call, "args", (IRValue(MemSpace.CONST, const=0, size=4),),
        )
        try:
            return preflight(*args, **kwargs)
        finally:
            object.__setattr__(other_call, "args", (saved,))

    def seen_equal(*args, **kwargs):
        derived.append(args[0])
        return equal(*args, **kwargs)

    monkeypatch.setattr(
        target_owner,
        "prove_direct_near_call_target_binding_at_coordinates_8616",
        corrupt_then_restore,
    )
    monkeypatch.setattr(
        target_owner, "_conditional_facts_equal_8616", seen_equal,
    )
    assert owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )
    assert len(derived) == len(scope.preservations)


def test_standalone_consume_retains_independent_graph_seals(monkeypatch):
    """Outside the scope, the consumer still captures its own caller graphs."""
    from inertia.ir import near_call_jump_scope as owner
    from inertia.ir import near_call_preservation as preservation
    from tests.ir.test_near_call_preservation import _consume

    surface, scope, _ = _scoped_loop()
    original = preservation.capture_immutable_source_graph_facts_8616
    captured = []

    def capture(*args, **kwargs):
        captured.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(
        preservation, 'capture_immutable_source_graph_facts_8616', capture,
    )
    assert owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )
    assert captured == []
    assert _consume(surface, scope.preservations[0])
    assert captured == [surface.artifact.function_addr] * 2


@pytest.mark.parametrize("address", [0x1000, 0x1008, 0x1010])
def test_final_entry_callback_cannot_change_live_native_census(monkeypatch, address):
    """Final entry replay cannot invalidate incoming, caller or callee bytes."""
    from inertia.ir import near_call_jump_scope as owner

    surface, scope = _scoped_two_call()
    original = owner.consume_native_near_call_entry_8616
    calls = 0

    def mutate(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            surface.project.loader.memory.store(address, b"\x90")
        return result

    monkeypatch.setattr(owner, "consume_native_near_call_entry_8616", mutate)
    assert not owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )


def test_staged_result_cannot_be_used_as_boolean_proof():
    """Both staged outcomes require explicit status and final census sealing."""
    from inertia.ir.near_call_preservation import _ScopedCensusStep8616, _ScopedCensusStepStatus8616

    for status in _ScopedCensusStepStatus8616:
        with pytest.raises(TypeError, match="final whole-census seal"):
            bool(_ScopedCensusStep8616(status))


def test_final_derivation_rejects_temporarily_repaired_forgery(monkeypatch):
    """Restored forged stats cannot borrow authority from a transient repair."""
    from inertia.ir import near_call_jump_scope as owner
    from inertia.ir import near_call_preservation as preservation

    surface, scope = _scoped_two_call()
    theorem = scope.preservations[0].theorem
    authentic = theorem.stats
    forged = replace(authentic, classified_fact_count=authentic.classified_fact_count + 1)
    object.__setattr__(theorem, "stats", forged)
    original = preservation._staged_scoped_theorem_8616

    def repaired(*args, **kwargs):
        object.__setattr__(theorem, "stats", authentic)
        try:
            return original(*args, **kwargs)
        finally:
            object.__setattr__(theorem, "stats", forged)

    monkeypatch.setattr(preservation, "_staged_scoped_theorem_8616", repaired)
    assert not owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )
    # Pin why the final pure derivation is necessary: all other seals alone
    # accept this stable forgery, even though the staged callback saw a repair.
    monkeypatch.setattr(owner, "_derive_final_scoped_theorem_8616", lambda *a, **k: True)
    assert owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )


def test_stable_forged_non_call_ir_requires_root_rebind(monkeypatch):
    """Stable pre-snapshot corruption is rejected by native root authority."""
    from inertia.ir import near_call_jump_scope as owner

    surface, scope = _scoped_two_call()
    instruction = next(i for b in surface.artifact.blocks for i in b.instrs if i.op != "CALL")
    object.__setattr__(instruction, "op", "CHANGED")
    assert not owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )
    monkeypatch.setattr(owner, "_rebind_raw_root_8616", lambda *a, **k: True)
    assert owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )


def test_final_derivation_follows_native_and_source_seals(monkeypatch):
    """No native callback follows final rooted per-call derivation."""
    from inertia.ir import near_call_jump_scope as owner

    surface, scope = _scoped_two_call()
    events = []

    def tracked(name, original):
        def call(*args, **kwargs):
            result = original(*args, **kwargs)
            events.append(name)
            return result
        return call

    for name, label in (
        ("consume_native_near_call_entry_8616", "native"),
        ("_native_census_facts_8616", "native"),
        ("_caller_census_unchanged_8616", "source"),
        ("_derive_final_scoped_theorem_8616", "derive"),
    ):
        monkeypatch.setattr(owner, name, tracked(label, getattr(owner, name)))
    assert owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )
    assert events[-3:] == ["source", "derive", "derive"]
    assert events.count("derive") == 2


def test_staged_target_is_not_boolean_proof():
    """Target staging alone cannot be consumed as an admitted result."""
    from inertia.semantics.conditional_near_call_target import _ScopedTargetStage8616

    for outcome in _ScopedTargetStage8616:
        with pytest.raises(TypeError, match="final whole-census seal"):
            bool(outcome)


def test_final_dependency_callback_must_precede_graph_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dependency proof callbacks finish before the caller graph is sealed."""
    from inertia.ir import near_call_jump_scope as owner
    from inertia.ir.core import IRRefusal
    surface, scope, _ = _scoped_loop()
    original = owner._dependency_facts_8616
    calls = 0
    def observed(current):
        nonlocal calls
        result = original(current)
        calls += 1
        if calls == 2:
            object.__setattr__(surface.artifact, "refusals", (
                *surface.artifact.refusals,
                IRRefusal("late", "changed during dependency proof", surface.artifact.function_addr),
            ))
        return result
    monkeypatch.setattr(owner, "_dependency_facts_8616", observed)
    assert not owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )


def test_native_read_cannot_mutate_sealed_dependencies(monkeypatch: pytest.MonkeyPatch) -> None:
    """Native observations must not bypass the existing dependency comparison."""
    from inertia.ir import near_call_jump_scope as owner
    surface, scope, _ = _scoped_loop()
    original = owner._native_census_facts_8616
    calls = 0
    def observed(current):
        nonlocal calls
        result = original(current)
        calls += 1
        if calls == 2:
            callee = scope.preservations[0].callee
            object.__setattr__(callee, "raw_fact_count", callee.raw_fact_count + 1)
        return result
    monkeypatch.setattr(owner, "_native_census_facts_8616", observed)
    assert not owner.authenticate_near_call_jump_scope_8616(
        scope, project=surface.project, artifact=surface.artifact,
    )
